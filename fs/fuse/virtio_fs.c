// SPDX-License-Identifier: GPL-2.0
/*
 * virtio-fs: Virtio Filesystem
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_fs.h>
#include <linux/delay.h>
#include "fuse_i.h"

/* List of virtio-fs device instances and a lock for the list */
static DEFINE_MUTEX(virtio_fs_mutex);
static LIST_HEAD(virtio_fs_instances);

enum {
	VQ_HIPRIO,
	VQ_REQUEST
};

/* Per-virtqueue state */
struct virtio_fs_vq {
	spinlock_t lock;
	struct virtqueue *vq;     /* protected by ->lock */
	struct work_struct done_work;
	struct list_head queued_reqs;
	struct delayed_work dispatch_work;
	struct fuse_dev *fud;
	bool connected;
	long in_flight;
	char name[24];
} ____cacheline_aligned_in_smp;

/* A virtio-fs device instance */
struct virtio_fs {
	struct list_head list;    /* on virtio_fs_instances */
	char *tag;
	struct virtio_fs_vq *vqs;
	unsigned nvqs;            /* number of virtqueues */
	unsigned num_queues;      /* number of request queues */
};

struct virtio_fs_forget {
	struct fuse_in_header ih;
	struct fuse_forget_in arg;
	/* This request can be temporarily queued on virt queue */
	struct list_head list;
};

static inline struct virtio_fs_vq *vq_to_fsvq(struct virtqueue *vq)
{
	struct virtio_fs *fs = vq->vdev->priv;

	return &fs->vqs[vq->index];
}

static inline struct fuse_pqueue *vq_to_fpq(struct virtqueue *vq)
{
	return &vq_to_fsvq(vq)->fud->pq;
}

/* Add a new instance to the list or return -EEXIST if tag name exists*/
static int virtio_fs_add_instance(struct virtio_fs *fs)
{
	struct virtio_fs *fs2;
	bool duplicate = false;

	mutex_lock(&virtio_fs_mutex);

	list_for_each_entry(fs2, &virtio_fs_instances, list) {
		if (strcmp(fs->tag, fs2->tag) == 0)
			duplicate = true;
	}

	if (!duplicate)
		list_add_tail(&fs->list, &virtio_fs_instances);

	mutex_unlock(&virtio_fs_mutex);

	if (duplicate)
		return -EEXIST;
	return 0;
}

/* Return the virtio_fs with a given tag, or NULL */
static struct virtio_fs *virtio_fs_find_instance(const char *tag)
{
	struct virtio_fs *fs;

	mutex_lock(&virtio_fs_mutex);

	list_for_each_entry(fs, &virtio_fs_instances, list) {
		if (strcmp(fs->tag, tag) == 0)
			goto found;
	}

	fs = NULL; /* not found */

found:
	mutex_unlock(&virtio_fs_mutex);

	return fs;
}

static void virtio_fs_free_devs(struct virtio_fs *fs)
{
	unsigned int i;

	/* TODO lock */

	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		if (!fsvq->fud)
			continue;

		flush_work(&fsvq->done_work);
		flush_delayed_work(&fsvq->dispatch_work);

		fuse_dev_free(fsvq->fud); /* TODO need to quiesce/end_requests/decrement dev_count */
		fsvq->fud = NULL;
	}
}

/* Read filesystem name from virtio config into fs->tag (must kfree()). */
static int virtio_fs_read_tag(struct virtio_device *vdev, struct virtio_fs *fs)
{
	char tag_buf[sizeof_field(struct virtio_fs_config, tag)];
	char *end;
	size_t len;

	virtio_cread_bytes(vdev, offsetof(struct virtio_fs_config, tag),
			   &tag_buf, sizeof(tag_buf));
	end = memchr(tag_buf, '\0', sizeof(tag_buf));
	if (end == tag_buf)
		return -EINVAL; /* empty tag */
	if (!end)
		end = &tag_buf[sizeof(tag_buf)];

	len = end - tag_buf;
	fs->tag = devm_kmalloc(&vdev->dev, len + 1, GFP_KERNEL);
	if (!fs->tag)
		return -ENOMEM;
	memcpy(fs->tag, tag_buf, len);
	fs->tag[len] = '\0';
	return 0;
}

/* Work function for hiprio completion */
static void virtio_fs_hiprio_done_work(struct work_struct *work)
{
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 done_work);
	struct virtqueue *vq = fsvq->vq;

	/* Free completed FUSE_FORGET requests */
	spin_lock(&fsvq->lock);
	do {
		unsigned len;
		void *req;

		virtqueue_disable_cb(vq);

		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
			kfree(req);
			fsvq->in_flight--;
		}
	} while (!virtqueue_enable_cb(vq) && likely(!virtqueue_is_broken(vq)));
	spin_unlock(&fsvq->lock);
}

static void virtio_fs_dummy_dispatch_work(struct work_struct *work)
{
	return;
}

static void virtio_fs_hiprio_dispatch_work(struct work_struct *work)
{
	struct virtio_fs_forget *forget;
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 dispatch_work.work);
	struct virtqueue *vq = fsvq->vq;
	struct scatterlist sg;
	struct scatterlist *sgs[] = {&sg};
	bool notify;
	int ret;

	pr_debug("worker virtio_fs_hiprio_dispatch_work() called.\n");
	while(1) {
		spin_lock(&fsvq->lock);
		forget = list_first_entry_or_null(&fsvq->queued_reqs,
					struct virtio_fs_forget, list);
		if (!forget) {
			spin_unlock(&fsvq->lock);
			return;
		}

		list_del(&forget->list);
		if (!fsvq->connected) {
			spin_unlock(&fsvq->lock);
			kfree(forget);
			continue;
		}

		sg_init_one(&sg, forget, sizeof(*forget));

		/* Enqueue the request */
		dev_dbg(&vq->vdev->dev, "%s\n", __func__);
		ret = virtqueue_add_sgs(vq, sgs, 1, 0, forget, GFP_ATOMIC);
		if (ret < 0) {
			if (ret == -ENOMEM || ret == -ENOSPC) {
				pr_debug("virtio-fs: Could not queue FORGET:"
					 " err=%d. Will try later\n", ret);
				list_add_tail(&forget->list,
						&fsvq->queued_reqs);
				schedule_delayed_work(&fsvq->dispatch_work,
						msecs_to_jiffies(1));
			} else {
				pr_debug("virtio-fs: Could not queue FORGET:"
					 " err=%d. Dropping it.\n", ret);
				kfree(forget);
			}
			spin_unlock(&fsvq->lock);
			return;
		}

		fsvq->in_flight++;
		notify = virtqueue_kick_prepare(vq);
		spin_unlock(&fsvq->lock);

		if (notify)
			virtqueue_notify(vq);
		pr_debug("worker virtio_fs_hiprio_dispatch_work() dispatched one forget request.\n");
	}
}

/* Allocate and copy args into req->argbuf */
static int copy_args_to_argbuf(struct fuse_req *req)
{
	unsigned offset = 0;
	unsigned num_in;
	unsigned num_out;
	unsigned len;
	unsigned i;

	num_in = req->in.numargs - req->in.argpages;
	num_out = req->out.numargs - req->out.argpages;
	len = fuse_len_args(num_in, (struct fuse_arg *)req->in.args) +
	      fuse_len_args(num_out, req->out.args);

	req->argbuf = kmalloc(len, GFP_ATOMIC);
	if (!req->argbuf)
		return -ENOMEM;

	for (i = 0; i < num_in; i++) {
		memcpy(req->argbuf + offset,
		       req->in.args[i].value,
		       req->in.args[i].size);
		offset += req->in.args[i].size;
	}

	return 0;
}

/* Copy args out of and free req->argbuf */
static void copy_args_from_argbuf(struct fuse_req *req)
{
	unsigned remaining;
	unsigned offset;
	unsigned num_in;
	unsigned num_out;
	unsigned i;

	remaining = req->out.h.len - sizeof(req->out.h);
	num_in = req->in.numargs - req->in.argpages;
	num_out = req->out.numargs - req->out.argpages;
	offset = fuse_len_args(num_in, (struct fuse_arg *)req->in.args);

	for (i = 0; i < num_out; i++) {
		unsigned argsize = req->out.args[i].size;

		if (req->out.argvar &&
		    i == req->out.numargs - 1 &&
		    argsize > remaining) {
			argsize = remaining;
		}

		memcpy(req->out.args[i].value, req->argbuf + offset, argsize);
		offset += argsize;

		if (i != req->out.numargs - 1)
			remaining -= argsize;
	}

	/* Store the actual size of the variable-length arg */
	if (req->out.argvar)
		req->out.args[req->out.numargs - 1].size = remaining;

	kfree(req->argbuf);
	req->argbuf = NULL;
}

/* Work function for request completion */
static void virtio_fs_requests_done_work(struct work_struct *work)
{
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 done_work);
	struct fuse_pqueue *fpq = &fsvq->fud->pq;
	struct fuse_conn *fc = fsvq->fud->fc;
	struct virtqueue *vq = fsvq->vq;
	struct fuse_req *req;
	struct fuse_req *next;
	LIST_HEAD(reqs);

	/* Collect completed requests off the virtqueue */
	spin_lock(&fsvq->lock);
	do {
		unsigned len;

		virtqueue_disable_cb(vq);

		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
			spin_lock(&fpq->lock);
			list_move_tail(&req->list, &reqs);
			spin_unlock(&fpq->lock);
		}
	} while (!virtqueue_enable_cb(vq) && likely(!virtqueue_is_broken(vq)));
	spin_unlock(&fsvq->lock);

	/* End requests */
	list_for_each_entry_safe(req, next, &reqs, list) {
		/* TODO check unique */
		/* TODO fuse_len_args(out) against oh.len */

		copy_args_from_argbuf(req);

		/* TODO zeroing? */

		spin_lock(&fpq->lock);
		clear_bit(FR_SENT, &req->flags);
		list_del_init(&req->list);
		spin_unlock(&fpq->lock);

		fuse_request_end(fc, req);
	}
}

/* Virtqueue interrupt handler */
static void virtio_fs_vq_done(struct virtqueue *vq)
{
	struct virtio_fs_vq *fsvq = vq_to_fsvq(vq);

	dev_dbg(&vq->vdev->dev, "%s %s\n", __func__, fsvq->name);

	schedule_work(&fsvq->done_work);
}

/* Initialize virtqueues */
static int virtio_fs_setup_vqs(struct virtio_device *vdev,
			       struct virtio_fs *fs)
{
	struct virtqueue **vqs;
	vq_callback_t **callbacks;
	const char **names;
	unsigned i;
	int ret;

	virtio_cread(vdev, struct virtio_fs_config, num_queues,
		     &fs->num_queues);
	if (fs->num_queues == 0)
		return -EINVAL;

	fs->nvqs = 1 + fs->num_queues;

	fs->vqs = devm_kcalloc(&vdev->dev, fs->nvqs,
				sizeof(fs->vqs[VQ_HIPRIO]), GFP_KERNEL);
	if (!fs->vqs)
		return -ENOMEM;

	vqs = kmalloc_array(fs->nvqs, sizeof(vqs[VQ_HIPRIO]), GFP_KERNEL);
	callbacks = kmalloc_array(fs->nvqs, sizeof(callbacks[VQ_HIPRIO]),
					GFP_KERNEL);
	names = kmalloc_array(fs->nvqs, sizeof(names[VQ_HIPRIO]), GFP_KERNEL);
	if (!vqs || !callbacks || !names) {
		ret = -ENOMEM;
		goto out;
	}

	callbacks[VQ_HIPRIO] = virtio_fs_vq_done;
	snprintf(fs->vqs[VQ_HIPRIO].name, sizeof(fs->vqs[VQ_HIPRIO].name),
			"hiprio");
	names[VQ_HIPRIO] = fs->vqs[VQ_HIPRIO].name;
	INIT_WORK(&fs->vqs[VQ_HIPRIO].done_work, virtio_fs_hiprio_done_work);
	INIT_LIST_HEAD(&fs->vqs[VQ_HIPRIO].queued_reqs);
	INIT_DELAYED_WORK(&fs->vqs[VQ_HIPRIO].dispatch_work,
			virtio_fs_hiprio_dispatch_work);
	spin_lock_init(&fs->vqs[VQ_HIPRIO].lock);

	/* Initialize the requests virtqueues */
	for (i = VQ_REQUEST; i < fs->nvqs; i++) {
		spin_lock_init(&fs->vqs[i].lock);
		INIT_WORK(&fs->vqs[i].done_work, virtio_fs_requests_done_work);
		INIT_DELAYED_WORK(&fs->vqs[i].dispatch_work,
					virtio_fs_dummy_dispatch_work);
		INIT_LIST_HEAD(&fs->vqs[i].queued_reqs);
		snprintf(fs->vqs[i].name, sizeof(fs->vqs[i].name),
			 "requests.%u", i - VQ_REQUEST);
		callbacks[i] = virtio_fs_vq_done;
		names[i] = fs->vqs[i].name;
	}

	ret = virtio_find_vqs(vdev, fs->nvqs, vqs, callbacks, names, NULL);
	if (ret < 0)
		goto out;

	for (i = 0; i < fs->nvqs; i++) {
		fs->vqs[i].vq = vqs[i];
		fs->vqs[i].connected = true;
	}
out:
	kfree(names);
	kfree(callbacks);
	kfree(vqs);
	return ret;
}

/* Free virtqueues (device must already be reset) */
static void virtio_fs_cleanup_vqs(struct virtio_device *vdev,
				  struct virtio_fs *fs)
{
	vdev->config->del_vqs(vdev);
}

static int virtio_fs_probe(struct virtio_device *vdev)
{
	struct virtio_fs *fs;
	int ret;

	fs = devm_kzalloc(&vdev->dev, sizeof(*fs), GFP_KERNEL);
	if (!fs)
		return -ENOMEM;
	vdev->priv = fs;

	ret = virtio_fs_read_tag(vdev, fs);
	if (ret < 0)
		goto out;

	ret = virtio_fs_setup_vqs(vdev, fs);
	if (ret < 0)
		goto out;

	/* TODO vq affinity */
	/* TODO populate notifications vq */

	/* Bring the device online in case the filesystem is mounted and
	 * requests need to be sent before we return.
	 */
	virtio_device_ready(vdev);

	ret = virtio_fs_add_instance(fs);
	if (ret < 0)
		goto out_vqs;

	return 0;

out_vqs:
	vdev->config->reset(vdev);
	virtio_fs_cleanup_vqs(vdev, fs);

out:
	vdev->priv = NULL;
	return ret;
}

static void virtio_fs_remove(struct virtio_device *vdev)
{
	struct virtio_fs *fs = vdev->priv;

	virtio_fs_free_devs(fs);

	vdev->config->reset(vdev);
	virtio_fs_cleanup_vqs(vdev, fs);

	mutex_lock(&virtio_fs_mutex);
	list_del(&fs->list);
	mutex_unlock(&virtio_fs_mutex);

	vdev->priv = NULL;
}

#ifdef CONFIG_PM
static int virtio_fs_freeze(struct virtio_device *vdev)
{
	return 0; /* TODO */
}

static int virtio_fs_restore(struct virtio_device *vdev)
{
	return 0; /* TODO */
}
#endif /* CONFIG_PM */

const static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_FS, VIRTIO_DEV_ANY_ID },
	{},
};

const static unsigned int feature_table[] = {};

static struct virtio_driver virtio_fs_driver = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= feature_table,
	.feature_table_size	= ARRAY_SIZE(feature_table),
	/* TODO validate config_get != NULL */
	.probe			= virtio_fs_probe,
	.remove			= virtio_fs_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze			= virtio_fs_freeze,
	.restore		= virtio_fs_restore,
#endif
};

static void virtio_fs_wake_forget_and_unlock(struct fuse_iqueue *fiq)
__releases(fiq->waitq.lock)
{
	struct fuse_forget_link *link;
	struct virtio_fs_forget *forget;
	struct scatterlist sg;
	struct scatterlist *sgs[] = {&sg};
	struct virtio_fs *fs;
	struct virtqueue *vq;
	struct virtio_fs_vq *fsvq;
	bool notify;
	u64 unique;
	int ret;

	link = fuse_dequeue_forget(fiq, 1, NULL);
	unique = fuse_get_unique(fiq);

	fs = fiq->priv;
	fsvq = &fs->vqs[VQ_HIPRIO];
	spin_unlock(&fiq->waitq.lock);

	/* Allocate a buffer for the request */
	forget = kmalloc(sizeof(*forget), GFP_ATOMIC);
	if (!forget) {
		pr_err("virtio-fs: dropped FORGET: kmalloc failed\n");
		goto out; /* TODO avoid dropping it? */
	}

	forget->ih = (struct fuse_in_header){
		.opcode = FUSE_FORGET,
		.nodeid = link->forget_one.nodeid,
		.unique = unique,
		.len = sizeof(*forget),
	};
	forget->arg = (struct fuse_forget_in){
		.nlookup = link->forget_one.nlookup,
	};

	sg_init_one(&sg, forget, sizeof(*forget));

	/* Enqueue the request */
	vq = fsvq->vq;
	dev_dbg(&vq->vdev->dev, "%s\n", __func__);
	spin_lock(&fsvq->lock);

	ret = virtqueue_add_sgs(vq, sgs, 1, 0, forget, GFP_ATOMIC);
	if (ret < 0) {
		if (ret == -ENOMEM || ret == -ENOSPC) {
			pr_debug("virtio-fs: Could not queue FORGET: err=%d."
				 " Will try later.\n", ret);
			list_add_tail(&forget->list, &fsvq->queued_reqs);
			schedule_delayed_work(&fsvq->dispatch_work,
					msecs_to_jiffies(1));
		} else {
			pr_debug("virtio-fs: Could not queue FORGET: err=%d."
				 " Dropping it.\n", ret);
			kfree(forget);
		}
		spin_unlock(&fsvq->lock);
		goto out;
	}

	fsvq->in_flight++;
	notify = virtqueue_kick_prepare(vq);

	spin_unlock(&fsvq->lock);

	if (notify)
		virtqueue_notify(vq);
out:
	kfree(link);
}

static void virtio_fs_wake_interrupt_and_unlock(struct fuse_iqueue *fiq)
__releases(fiq->waitq.lock)
{
	/* TODO */
	spin_unlock(&fiq->waitq.lock);
}

/* Return the number of scatter-gather list elements required */
static unsigned sg_count_fuse_req(struct fuse_req *req)
{
	unsigned total_sgs = 1 /* fuse_in_header */;

	if (req->in.numargs - req->in.argpages)
		total_sgs += 1;

	if (req->in.argpages)
		total_sgs += req->num_pages;

	if (!test_bit(FR_ISREPLY, &req->flags))
		return total_sgs;

	total_sgs += 1 /* fuse_out_header */;

	if (req->out.numargs - req->out.argpages)
		total_sgs += 1;

	if (req->out.argpages)
		total_sgs += req->num_pages;

	return total_sgs;
}

/* Add pages to scatter-gather list and return number of elements used */
static unsigned sg_init_fuse_pages(struct scatterlist *sg,
				   struct page **pages,
				   struct fuse_page_desc *page_descs,
				   unsigned num_pages)
{
	unsigned i;

	for (i = 0; i < num_pages; i++) {
		sg_init_table(&sg[i], 1);
		sg_set_page(&sg[i], pages[i],
			    page_descs[i].length,
			    page_descs[i].offset);
	}

	return i;
}

/* Add args to scatter-gather list and return number of elements used */
static unsigned sg_init_fuse_args(struct scatterlist *sg,
				  struct fuse_req *req,
				  struct fuse_arg *args,
				  unsigned numargs,
				  bool argpages,
				  void *argbuf,
				  unsigned *len_used)
{
	unsigned total_sgs = 0;
	unsigned len;

	len = fuse_len_args(numargs - argpages, args);
	if (len)
		sg_init_one(&sg[total_sgs++], argbuf, len);

	if (argpages)
		total_sgs += sg_init_fuse_pages(&sg[total_sgs],
						req->pages,
						req->page_descs,
						req->num_pages);

	if (len_used)
		*len_used = len;

	return total_sgs;
}

/* Add a request to a virtqueue and kick the device */
static int virtio_fs_enqueue_req(struct virtqueue *vq, struct fuse_req *req)
{
	struct scatterlist *stack_sgs[6 /* requests need at least 4 elements */];
	struct scatterlist stack_sg[ARRAY_SIZE(stack_sgs)];
	struct scatterlist **sgs = stack_sgs;
	struct scatterlist *sg = stack_sg;
	struct virtio_fs_vq *fsvq;
	unsigned argbuf_used = 0;
	unsigned out_sgs = 0;
	unsigned in_sgs = 0;
	unsigned total_sgs;
	unsigned i;
	int ret;
	bool notify;

	/* Does the sglist fit on the stack? */
	total_sgs = sg_count_fuse_req(req);
	if (total_sgs > ARRAY_SIZE(stack_sgs)) {
		sgs = kmalloc_array(total_sgs, sizeof(sgs[0]), GFP_ATOMIC);
		sg = kmalloc_array(total_sgs, sizeof(sg[0]), GFP_ATOMIC);
		if (!sgs || !sg) {
			ret = -ENOMEM;
			goto out;
		}
	}

	/* Use a bounce buffer since stack args cannot be mapped */
	ret = copy_args_to_argbuf(req);
	if (ret < 0)
		goto out;

	/* Request elements */
	sg_init_one(&sg[out_sgs++], &req->in.h, sizeof(req->in.h));
	out_sgs += sg_init_fuse_args(&sg[out_sgs], req,
				     (struct fuse_arg *)req->in.args,
				     req->in.numargs, req->in.argpages,
				     req->argbuf, &argbuf_used);

	/* Reply elements */
	if (test_bit(FR_ISREPLY, &req->flags)) {
		sg_init_one(&sg[out_sgs + in_sgs++],
			    &req->out.h, sizeof(req->out.h));
		in_sgs += sg_init_fuse_args(&sg[out_sgs + in_sgs], req,
					    req->out.args, req->out.numargs,
					    req->out.argpages,
					    req->argbuf + argbuf_used, NULL);
	}

	BUG_ON(out_sgs + in_sgs != total_sgs);

	for (i = 0; i < total_sgs; i++)
		sgs[i] = &sg[i];

	fsvq = vq_to_fsvq(vq);
	spin_lock(&fsvq->lock);

	ret = virtqueue_add_sgs(vq, sgs, out_sgs, in_sgs, req, GFP_ATOMIC);
	if (ret < 0) {
		/* TODO handle full virtqueue */
		spin_unlock(&fsvq->lock);
		goto out;
	}

	notify = virtqueue_kick_prepare(vq);

	spin_unlock(&fsvq->lock);

	if (notify)
		virtqueue_notify(vq);

out:
	if (ret < 0 && req->argbuf) {
		kfree(req->argbuf);
		req->argbuf = NULL;
	}
	if (sgs != stack_sgs) {
		kfree(sgs);
		kfree(sg);
	}

	return ret;
}

static void virtio_fs_wake_pending_and_unlock(struct fuse_iqueue *fiq)
__releases(fiq->waitq.lock)
{
	unsigned queue_id = VQ_REQUEST; /* TODO multiqueue */
	struct virtio_fs *fs;
	struct fuse_conn *fc;
	struct fuse_req *req;
	struct fuse_pqueue *fpq;
	int ret;

	BUG_ON(list_empty(&fiq->pending));
	req = list_last_entry(&fiq->pending, struct fuse_req, list);
	clear_bit(FR_PENDING, &req->flags);
	list_del_init(&req->list);
	BUG_ON(!list_empty(&fiq->pending));
	spin_unlock(&fiq->waitq.lock);

	fs = fiq->priv;
	fc = fs->vqs[queue_id].fud->fc;

	dev_dbg(&fs->vqs[queue_id].vq->vdev->dev,
		"%s: opcode %u unique %#llx nodeid %#llx in.len %u out.len %u\n",
		__func__, req->in.h.opcode, req->in.h.unique, req->in.h.nodeid,
		req->in.h.len, fuse_len_args(req->out.numargs, req->out.args));

	fpq = &fs->vqs[queue_id].fud->pq;
	spin_lock(&fpq->lock);
	if (!fpq->connected) {
		spin_unlock(&fpq->lock);
		req->out.h.error = -ENODEV;
		printk(KERN_ERR "%s: disconnected\n", __func__);
		fuse_request_end(fc, req);
		return;
	}
	list_add_tail(&req->list, fpq->processing);
	spin_unlock(&fpq->lock);
	set_bit(FR_SENT, &req->flags);
	/* matches barrier in request_wait_answer() */
	smp_mb__after_atomic();
	/* TODO check for FR_INTERRUPTED? */

retry:
	ret = virtio_fs_enqueue_req(fs->vqs[queue_id].vq, req);
	if (ret < 0) {
		if (ret == -ENOMEM || ret == -ENOSPC) {
			/* Virtqueue full. Retry submission */
			usleep_range(20, 30);
			goto retry;
		}
		req->out.h.error = ret;
		printk(KERN_ERR "%s: virtio_fs_enqueue_req failed %d\n",
			__func__, ret);
		fuse_request_end(fc, req);
		return;
	}
}

static void virtio_fs_flush_hiprio_queue(struct virtio_fs_vq *fsvq)
{
	struct virtio_fs_forget *forget;

	WARN_ON(fsvq->in_flight < 0);

	/* Go through pending forget reuests and free them */
	spin_lock(&fsvq->lock);
	while(1) {
		forget = list_first_entry_or_null(&fsvq->queued_reqs,
					struct virtio_fs_forget, list);
		if (!forget)
			break;
		list_del(&forget->list);
		kfree(forget);
	}

	spin_unlock(&fsvq->lock);

	/* Wait for in flight requests to finish.*/
	while (1) {
		spin_lock(&fsvq->lock);
		if (!fsvq->in_flight) {
			spin_unlock(&fsvq->lock);
			break;
		}
		spin_unlock(&fsvq->lock);
		usleep_range(1000, 2000);
	}
}

const static struct fuse_iqueue_ops virtio_fs_fiq_ops = {
	.wake_forget_and_unlock		= virtio_fs_wake_forget_and_unlock,
	.wake_interrupt_and_unlock	= virtio_fs_wake_interrupt_and_unlock,
	.wake_pending_and_unlock	= virtio_fs_wake_pending_and_unlock,
};

static int virtio_fs_fill_super(struct super_block *sb, char *opts,
				struct fuse_mount_data *d)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct virtio_fs *fs = fc->iq.priv;
	unsigned int i;
	int err;
	struct fuse_req *init_req;

	/* TODO lock */
	if (fs->vqs[VQ_REQUEST].fud) {
		printk(KERN_ERR "virtio-fs: device already in use\n");
		err = -EBUSY;
		goto err;
	}

	err = -ENOMEM;
	/* Allocate fuse_dev for hiprio and notification queues */
	for (i = 0; i < VQ_REQUEST; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		fsvq->fud = fuse_dev_alloc();
		if (!fsvq->fud)
			goto err_free_fuse_devs;
	}

	init_req = fuse_request_alloc(0);
	if (!init_req)
		goto err_free_fuse_devs;
	__set_bit(FR_BACKGROUND, &init_req->flags);

	d->fudptr = (void **)&fs->vqs[VQ_REQUEST].fud;
	d->destroy = true; /* Send destroy request on unmount */
	err = fuse_fill_super_common(sb, d);
	if (err < 0)
		goto err_free_init_req;

	fc = fs->vqs[VQ_REQUEST].fud->fc;

	/* TODO take fuse_mutex around this loop? */
	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		if (i == VQ_REQUEST)
			continue; /* already initialized */
		fuse_dev_install(fsvq->fud, fc);
		atomic_inc(&fc->dev_count);
	}

	fuse_send_init(fc, init_req);
	return 0;

err_free_init_req:
	fuse_request_free(init_req);
err_free_fuse_devs:
	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];
		fuse_dev_free(fsvq->fud);
	}
err:
	return err;
}

static void virtio_kill_sb(struct super_block *sb)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct virtio_fs *vfs;
	struct virtio_fs_vq *fsvq;

	/* If mount failed, we can still be called without any fc */
	if (!fc)
		return fuse_kill_sb_anon(sb);

	vfs = fc->iq.priv;
	fsvq = &vfs->vqs[VQ_HIPRIO];

	/* Stop forget queue. Soon destroy will be sent */
	spin_lock(&fsvq->lock);
	fsvq->connected = false;
	spin_unlock(&fsvq->lock);
	virtio_fs_flush_hiprio_queue(fsvq);

	fuse_kill_sb_anon(sb);
	virtio_fs_free_devs(vfs);
}

static int virtio_fs_test_super(struct super_block *s, void *data)
{
	struct fuse_conn *fc = data;

	return fc->iq.priv == get_fuse_conn_super(s)->iq.priv;

}

static int virtio_fs_set_super(struct super_block *s, void *data)
{
	int err;

	err = get_anon_bdev(&s->s_dev);
	if (!err)
		s->s_fs_info = fuse_conn_get(data);

	return err;
}

static struct dentry *virtio_fs_mount(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *opts)
{
	struct virtio_fs *fs;
	struct super_block *s;
	struct fuse_conn *fc;
	int err;
	struct fuse_mount_data d;

	fs = virtio_fs_find_instance(dev_name);
	if (!fs) {
		pr_info("virtio-fs: tag <%s> not found\n", dev_name);
		return ERR_PTR(-EINVAL);
	}

	if (!parse_fuse_opt(opts, &d, 0, current_user_ns()))
		return ERR_PTR(-EINVAL);

	if (d.fd_present) {
		printk(KERN_ERR "virtio-fs: fd option cannot be used\n");
		return ERR_PTR(-EINVAL);
	}

	fc = kzalloc(sizeof(struct fuse_conn), GFP_KERNEL);
	if (!fc)
		return ERR_PTR(-ENOMEM);
	d.dax_dev = NULL;
	fuse_conn_init(fc, get_user_ns(current_user_ns()), d.dax_dev,
		       &virtio_fs_fiq_ops, fs);
	fc->release = fuse_free_conn;

	s = sget(fs_type, virtio_fs_test_super, virtio_fs_set_super, flags, fc);
	err = PTR_ERR(s);
	if (IS_ERR(s))
		goto err_free_fc;

	err = -EIO;
	if (WARN_ON(fc->user_ns != s->s_user_ns))
		goto deactivate;

	if (s->s_root) {
		err = -EBUSY;
		if ((flags ^ s->s_flags) & SB_RDONLY)
			goto deactivate;
	} else {
		err = virtio_fs_fill_super(s, opts, &d);
		if (err)
			goto deactivate;

		s->s_flags |= SB_ACTIVE;
	}
	fuse_conn_put(fc);

	return dget(s->s_root);

deactivate:
        deactivate_locked_super(s);

err_free_fc:
	fuse_conn_put(fc);
	return ERR_PTR(err);
}

static struct file_system_type virtio_fs_type = {
	.owner		= THIS_MODULE,
	.name		= KBUILD_MODNAME,
	.mount		= virtio_fs_mount,
	.kill_sb	= virtio_kill_sb,
};

static int __init virtio_fs_init(void)
{
	int ret;

	ret = register_virtio_driver(&virtio_fs_driver);
	if (ret < 0)
		return ret;

	ret = register_filesystem(&virtio_fs_type);
	if (ret < 0) {
		unregister_virtio_driver(&virtio_fs_driver);
		return ret;
	}

	return 0;
}
module_init(virtio_fs_init);

static void __exit virtio_fs_exit(void)
{
	unregister_filesystem(&virtio_fs_type);
	unregister_virtio_driver(&virtio_fs_driver);
}
module_exit(virtio_fs_exit);

MODULE_AUTHOR("Stefan Hajnoczi <stefanha@redhat.com>");
MODULE_DESCRIPTION("Virtio Filesystem");
MODULE_LICENSE("GPL");
MODULE_ALIAS_FS(KBUILD_MODNAME);
MODULE_DEVICE_TABLE(virtio, id_table);

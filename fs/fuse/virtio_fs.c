// SPDX-License-Identifier: GPL-2.0
/*
 * virtio-fs: Virtio Filesystem
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_fs.h>
#include "fuse_i.h"

/* List of virtio-fs device instances and a lock for the list */
static DEFINE_MUTEX(virtio_fs_mutex);
static LIST_HEAD(virtio_fs_instances);

/* A virtio-fs device instance */
struct virtio_fs {
	struct list_head list; /* on virtio_fs_instances */
	char *tag;
	struct fuse_dev **fud; /* 1:1 mapping with request queues */
	unsigned int num_queues;
};

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

	if (!fs->fud)
		return;

	for (i = 0; i < fs->num_queues; i++) {
		struct fuse_dev *fud = fs->fud[i];

		if (fud)
			fuse_dev_free(fud); /* TODO need to quiesce/end_requests/decrement dev_count */
	}

	kfree(fs->fud);
	fs->fud = NULL;
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

static int virtio_fs_probe(struct virtio_device *vdev)
{
	struct virtio_fs *fs;
	int ret;

	fs = devm_kzalloc(&vdev->dev, sizeof(*fs), GFP_KERNEL);
	if (!fs)
		return -ENOMEM;
	vdev->priv = fs;

	virtio_cread(vdev, struct virtio_fs_config, num_queues,
		     &fs->num_queues);
	if (fs->num_queues == 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = virtio_fs_read_tag(vdev, fs);
	if (ret < 0)
		goto out;

	ret = virtio_fs_add_instance(fs);
	if (ret < 0)
		goto out;

	return 0;

out:
	vdev->priv = NULL;
	return ret;
}

static void virtio_fs_remove(struct virtio_device *vdev)
{
	struct virtio_fs *fs = vdev->priv;

	virtio_fs_free_devs(fs);

	vdev->config->reset(vdev);

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

static int virtio_fs_fill_super(struct super_block *sb, void *data,
				int silent)
{
	struct fuse_mount_data d;
	struct fuse_conn *fc;
	struct virtio_fs *fs;
	int is_bdev = sb->s_bdev != NULL;
	unsigned int i;
	int err;

	err = -EINVAL;
	if (!parse_fuse_opt(data, &d, is_bdev, sb->s_user_ns))
		goto err;
	if (d.fd_present) {
		printk(KERN_ERR "virtio-fs: fd option cannot be used\n");
		goto err;
	}
	if (!d.tag_present) {
		printk(KERN_ERR "virtio-fs: missing tag option\n");
		goto err;
	}

	fs = virtio_fs_find_instance(d.tag);
	if (!fs) {
		printk(KERN_ERR "virtio-fs: tag not found\n");
		err = -ENOENT;
		goto err;
	}

	/* TODO lock */
	if (fs->fud) {
		printk(KERN_ERR "virtio-fs: device already in use\n");
		err = -EBUSY;
		goto err;
	}
	fs->fud = kcalloc(fs->num_queues, sizeof(fs->fud[0]), GFP_KERNEL);
	if (!fs->fud) {
		err = -ENOMEM;
		goto err_fud;
	}

	err = fuse_fill_super_common(sb, &d, (void **)&fs->fud[0]);
	if (err < 0)
		goto err;

	fc = fs->fud[0]->fc;

	/* Allocate remaining fuse_devs */
	err = -ENOMEM;
	/* TODO take fuse_mutex around this loop? */
	for (i = 1; i < fs->num_queues; i++) {
		fs->fud[i] = fuse_dev_alloc_install(fc);
		if (!fs->fud[i]) {
			/* TODO */
		}
		atomic_inc(&fc->dev_count);
	}

	return 0;

err:
	return err;
}

static struct dentry *virtio_fs_mount(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, virtio_fs_fill_super);
}

static struct file_system_type virtio_fs_type = {
	.owner		= THIS_MODULE,
	.name		= KBUILD_MODNAME,
	.mount		= virtio_fs_mount,
	.kill_sb	= fuse_kill_sb_anon,
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

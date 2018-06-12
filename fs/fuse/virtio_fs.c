// SPDX-License-Identifier: GPL-2.0
/*
 * virtio-fs: Virtio Filesystem
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_fs.h>

/* List of virtio-fs device instances and a lock for the list */
static DEFINE_MUTEX(virtio_fs_mutex);
static LIST_HEAD(virtio_fs_instances);

/* A virtio-fs device instance */
struct virtio_fs {
	struct list_head list; /* on virtio_fs_instances */
	char *tag;
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

static struct file_system_type virtio_fs_type = {
	.owner		= THIS_MODULE,
	.name		= KBUILD_MODNAME,
	.mount		= NULL,
	.kill_sb	= NULL,
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

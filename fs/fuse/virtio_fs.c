// SPDX-License-Identifier: GPL-2.0
/*
 * virtio-fs: Virtio Filesystem
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include <linux/module.h>
#include <linux/fs.h>

MODULE_AUTHOR("Stefan Hajnoczi <stefanha@redhat.com>");
MODULE_DESCRIPTION("Virtio Filesystem");
MODULE_LICENSE("GPL");
MODULE_ALIAS_FS(KBUILD_MODNAME);

static struct file_system_type virtio_fs_type = {
	.owner		= THIS_MODULE,
	.name		= KBUILD_MODNAME,
	.mount		= NULL,
	.kill_sb	= NULL,
};

static int __init virtio_fs_init(void)
{
	return register_filesystem(&virtio_fs_type);
}

static void __exit virtio_fs_exit(void)
{
	unregister_filesystem(&virtio_fs_type);
}

module_init(virtio_fs_init);
module_exit(virtio_fs_exit);

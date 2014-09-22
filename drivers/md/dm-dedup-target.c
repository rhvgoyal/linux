/*
 * Copyright (C) 2012-2014 Vasily Tarasov
 * Copyright (C) 2012-2014 Geoff Kuenning
 * Copyright (C) 2012-2014 Sonam Mandal
 * Copyright (C) 2012-2014 Karthikeyani Palanisami
 * Copyright (C) 2012-2014 Philip Shilane
 * Copyright (C) 2012-2014 Sagar Trehan
 * Copyright (C) 2012-2014 Erez Zadok
 *
 * This file is released under the GPL.
 */

#include "dm-dedup-target.h"
#include "dm-dedup-rw.h"
#include "dm-dedup-hash.h"
#include "dm-dedup-backend.h"
#include "dm-dedup-ram.h"
#include "dm-dedup-cbt.h"
#include "dm-dedup-kvstore.h"

#define MAX_DEV_NAME_LEN (64)
#define MAX_BACKEND_NAME_LEN (64)

#define MIN_DATA_DEV_BLOCK_SIZE (4 * 1024)
#define MAX_DATA_DEV_BLOCK_SIZE (1024 * 1024)

struct on_disk_stats {
	uint64_t physical_block_counter;
	uint64_t logical_block_counter;
};

/*
 * All incoming requests are packed in the dedup_work structure
 * for further processing by the workqueue thread.
 */
struct dedup_work {
	struct work_struct worker;
	struct dedup_config *config;
	struct bio *bio;
};

struct mark_and_sweep_data {
	unsigned long *bitmap;
	uint64_t bitmap_len;
	uint64_t cleanup_count; /* number of hashes cleaned up */
	struct dedup_config *dc;
};

enum backend {
	BKND_INRAM,
	BKND_COWBTREE
};

static void bio_zero_endio(struct bio *bio)
{
	zero_fill_bio(bio);
	bio_endio(bio, 0);
}

static uint64_t bio_lbn(struct dedup_config *dc, struct bio *bio)
{
	return bio->bi_iter.bi_sector / dc->sectors_per_block;
}

static void do_io(struct dedup_config *dc, struct bio *bio,
			uint64_t pbn)
{
	int offset;

	offset = (sector_t) bio->bi_iter.bi_sector % dc->sectors_per_block;
	bio->bi_iter.bi_sector = (sector_t)pbn * dc->sectors_per_block + offset;

	bio->bi_bdev = dc->data_dev->bdev;

	generic_make_request(bio);
}

static void handle_read(struct dedup_config *dc, struct bio *bio)
{
	uint64_t lbn;
	uint32_t vsize;
	struct lbn_pbn_value lbnpbn_value;
	int r;

	lbn = bio_lbn(dc, bio);

	r = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
			sizeof(lbn), (void *)&lbnpbn_value, &vsize);
	if (r == 0)
		bio_zero_endio(bio);
	else if (r == 1)
		do_io(dc, bio, lbnpbn_value.pbn);
	else
		BUG();
}

static int allocate_block(struct dedup_config *dc, uint64_t *pbn_new)
{
	int r;

	r = dc->mdops->alloc_data_block(dc->bmd, pbn_new);

	if (!r) {
		dc->logical_block_counter++;
		dc->physical_block_counter++;
	}

	return r;
}

static int write_to_new_block(struct dedup_config *dc, uint64_t *pbn_new,
			      struct bio *bio, uint64_t lbn)
{
	int r = 0;
	struct lbn_pbn_value lbnpbn_value;

	r = allocate_block(dc, pbn_new);
	if (r < 0) {
		r = -EIO;
		return r;
	}

	lbnpbn_value.pbn = *pbn_new;

	do_io(dc, bio, *pbn_new);

	r = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn, (void *)&lbn,
		sizeof(lbn), (void *)&lbnpbn_value, sizeof(lbnpbn_value));
	if (r < 0)
		BUG();

	return r;
}

static int handle_write_no_hash(struct dedup_config *dc,
				struct bio *bio, uint64_t lbn, u8 *hash)
{
	int r;
	uint32_t vsize;
	uint64_t pbn_new, pbn_old;
	struct lbn_pbn_value lbnpbn_value;
	struct hash_pbn_value hashpbn_value;

	dc->uniqwrites++;

	r = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
			sizeof(lbn), (void *)&lbnpbn_value, &vsize);
	if (r == 0) {
		/* No LBN->PBN mapping entry */
		dc->newwrites++;
		r = write_to_new_block(dc, &pbn_new, bio, lbn);
		if (r < 0)
			goto out;

		hashpbn_value.pbn = pbn_new;

		r = dc->kvs_hash_pbn->kvs_insert(dc->kvs_hash_pbn, (void *)hash,
				dc->crypto_key_size, (void *)&hashpbn_value,
				sizeof(hashpbn_value));
		if (r < 0)
			BUG();

		r = dc->mdops->inc_refcount(dc->bmd, pbn_new);
		if (r < 0)
			BUG();

		goto out;
	} else if (r < 0)
		BUG();

	/* LBN->PBN mappings exist */
	dc->overwrites++;
	r = write_to_new_block(dc, &pbn_new, bio, lbn);
	if (r < 0)
		goto out;

	pbn_old = lbnpbn_value.pbn;
	r = dc->mdops->dec_refcount(dc->bmd, pbn_old);
	if (r < 0)
		BUG();

	dc->logical_block_counter--;

	hashpbn_value.pbn = pbn_new;

	r = dc->kvs_hash_pbn->kvs_insert(dc->kvs_hash_pbn, (void *)hash,
				dc->crypto_key_size, (void *)&hashpbn_value,
				sizeof(hashpbn_value));
	if (r < 0)
		BUG();

	r = dc->mdops->inc_refcount(dc->bmd, pbn_new);
	if (r < 0)
		BUG();
out:
	return r;
}

static int handle_write_with_hash(struct dedup_config *dc, struct bio *bio,
				  uint64_t lbn, u8 *final_hash,
				  struct hash_pbn_value hashpbn_value)
{
	int r;
	uint32_t vsize;
	uint64_t pbn_new, pbn_old;
	struct lbn_pbn_value lbnpbn_value;
	struct lbn_pbn_value new_lbnpbn_value;

	dc->dupwrites++;

	pbn_new = hashpbn_value.pbn;
	r = dc->kvs_lbn_pbn->kvs_lookup(dc->kvs_lbn_pbn, (void *)&lbn,
			sizeof(lbn), (void *)&lbnpbn_value, &vsize);
	if (r == 0) {
		/* No LBN->PBN mapping entry */
		dc->newwrites++;

		r = dc->mdops->inc_refcount(dc->bmd, pbn_new);
		if (r < 0)
			BUG();

		lbnpbn_value.pbn = pbn_new;

		r = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn, (void *)&lbn,
				sizeof(lbn), (void *)&lbnpbn_value,
				sizeof(lbnpbn_value));
		if (r < 0)
			BUG();

		dc->logical_block_counter++;

		goto out;
	} else if (r < 0)
		BUG();

	/* LBN->PBN mapping entry exists */
	dc->overwrites++;
	pbn_old = lbnpbn_value.pbn;
	if (pbn_new != pbn_old) {
		r = dc->mdops->inc_refcount(dc->bmd, pbn_new);
		if (r < 0)
			BUG();

		new_lbnpbn_value.pbn = pbn_new;

		r = dc->kvs_lbn_pbn->kvs_insert(dc->kvs_lbn_pbn, (void *)&lbn,
			sizeof(lbn), (void *)&new_lbnpbn_value,
			sizeof(new_lbnpbn_value));
		if (r < 0)
			BUG();

		r = dc->mdops->dec_refcount(dc->bmd, pbn_old);
		if (r < 0)
			BUG();

		goto out;
	}

	/* Nothing to do if writing same data to same LBN */

out:
	bio_endio(bio, 0);
	return r;
}

static void handle_write(struct dedup_config *dc, struct bio *bio)
{
	uint64_t lbn;
	u8 hash[MAX_DIGEST_SIZE];
	struct hash_pbn_value hashpbn_value;
	uint32_t vsize;
	struct bio *new_bio = NULL;
	int r;

	dc->writes++;

	/* Read-on-write handling */
	if (bio->bi_iter.bi_size < dc->block_size) {
		dc->reads_on_writes++;
		new_bio = prepare_bio_on_write(dc, bio);
		if (!new_bio) {
			bio_endio(bio, -ENOMEM);
			return;
		}
		bio = new_bio;
	}

	lbn = bio_lbn(dc, bio);

	r = compute_hash_bio(dc->desc_table, bio, hash);
	if (r)
		BUG();

	r = dc->kvs_hash_pbn->kvs_lookup(dc->kvs_hash_pbn, hash,
				dc->crypto_key_size, &hashpbn_value, &vsize);

	if (r == 0)
		r = handle_write_no_hash(dc, bio, lbn, hash);
	else if (r > 0)
		r = handle_write_with_hash(dc, bio, lbn, hash,
					hashpbn_value);
	else
		BUG();

	dc->writes_after_flush++;
	if ((dc->flushrq && dc->writes_after_flush >= dc->flushrq) ||
			(bio->bi_rw & (REQ_FLUSH | REQ_FUA))) {
		r = dc->mdops->flush_meta(dc->bmd);
		dc->writes_after_flush = 0;
	}
}

static void process_bio(struct dedup_config *dc, struct bio *bio)
{
	switch (bio_data_dir(bio)) {
	case READ:
		handle_read(dc, bio);
		break;
	case WRITE:
		handle_write(dc, bio);
		break;
	default:
		DMERR("Unknown request type!");
		bio_endio(bio, -EINVAL);
	}
}

static void do_work(struct work_struct *ws)
{
	struct dedup_work *data = container_of(ws, struct dedup_work, worker);
	struct dedup_config *dc = (struct dedup_config *)data->config;
	struct bio *bio = (struct bio *)data->bio;

	mempool_free(data, dc->dedup_work_pool);

	process_bio(dc, bio);
}

static void dedup_defer_bio(struct dedup_config *dc, struct bio *bio)
{
	struct dedup_work *data;

	data = mempool_alloc(dc->dedup_work_pool, GFP_NOIO);
	if (!data) {
		bio_endio(bio, -ENOMEM);
		return;
	}

	data->bio = bio;
	data->config = dc;

	INIT_WORK(&(data->worker), do_work);

	queue_work(dc->workqueue, &(data->worker));
}

static int dm_dedup_map(struct dm_target *ti, struct bio *bio)
{
	dedup_defer_bio(ti->private, bio);

	return DM_MAPIO_SUBMITTED;
}

struct dedup_args {
	struct dm_target *ti;

	struct dm_dev *meta_dev;

	struct dm_dev *data_dev;
	uint64_t data_size;

	uint32_t block_size;

	char hash_algo[CRYPTO_ALG_NAME_LEN];

	enum backend backend;

	uint32_t flushrq;
};

static int parse_meta_dev(struct dedup_args *da, struct dm_arg_set *as,
			  char **err)
{
	int r;

	r = dm_get_device(da->ti, dm_shift_arg(as),
			dm_table_get_mode(da->ti->table), &da->meta_dev);
	if (r)
		*err = "Error opening metadata device";

	return r;
}

static int parse_data_dev(struct dedup_args *da, struct dm_arg_set *as,
			  char **err)
{
	int r;

	r = dm_get_device(da->ti, dm_shift_arg(as),
			dm_table_get_mode(da->ti->table), &da->data_dev);
	if (r)
		*err = "Error opening data device";

	da->data_size = i_size_read(da->data_dev->bdev->bd_inode);

	return r;
}

static int parse_block_size(struct dedup_args *da, struct dm_arg_set *as,
			    char **err)
{
	uint32_t block_size;

	if (kstrtou32(dm_shift_arg(as), 10, &block_size) ||
		!block_size ||
		block_size < MIN_DATA_DEV_BLOCK_SIZE ||
		block_size > MAX_DATA_DEV_BLOCK_SIZE ||
		!is_power_of_2(block_size)) {
		*err = "Invalid data block size";
		return -EINVAL;
	}

	if (block_size > da->data_size) {
		*err = "Data block size is larger than the data device";
		return -EINVAL;
	}

	da->block_size = block_size;

	return 0;
}

static int parse_hash_algo(struct dedup_args *da, struct dm_arg_set *as,
			   char **err)
{
	strlcpy(da->hash_algo, dm_shift_arg(as), CRYPTO_ALG_NAME_LEN);

	if (!crypto_has_hash(da->hash_algo, 0, CRYPTO_ALG_ASYNC)) {
		*err = "Unrecognized hash algorithm";
		return -EINVAL;
	}

	return 0;
}

static int parse_backend(struct dedup_args *da, struct dm_arg_set *as,
			 char **err)
{
	char backend[MAX_BACKEND_NAME_LEN];

	strlcpy(backend, dm_shift_arg(as), MAX_BACKEND_NAME_LEN);

	if (!strcmp(backend, "inram"))
		da->backend = BKND_INRAM;
	else if (!strcmp(backend, "cowbtree"))
		da->backend = BKND_COWBTREE;
	else {
		*err = "Unsupported metadata backend";
		return -EINVAL;
	}

	return 0;
}

static int parse_flushrq(struct dedup_args *da, struct dm_arg_set *as,
			 char **err)
{
	if (kstrtou32(dm_shift_arg(as), 10, &da->flushrq))
		return -EINVAL;

	return 0;
}

static int parse_dedup_args(struct dedup_args *da, int argc,
			    char **argv, char **err)
{
	struct dm_arg_set as;
	int r;

	if (argc < 6) {
		*err = "Insufficient args";
		return -EINVAL;
	}

	if (argc > 6) {
		*err = "Too many args";
		return -EINVAL;
	}

	as.argc = argc;
	as.argv = argv;

	r = parse_meta_dev(da, &as, err);
	if (r)
		return r;

	r = parse_data_dev(da, &as, err);
	if (r)
		return r;

	r = parse_block_size(da, &as, err);
	if (r)
		return r;

	r = parse_hash_algo(da, &as, err);
	if (r)
		return r;

	r = parse_backend(da, &as, err);
	if (r)
		return r;

	r = parse_flushrq(da, &as, err);
	if (r)
		return r;

	return 0;
}

static void destroy_dedup_args(struct dedup_args *da)
{
	if (da->meta_dev)
		dm_put_device(da->ti, da->meta_dev);

	if (da->data_dev)
		dm_put_device(da->ti, da->data_dev);
}

static int dm_dedup_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dedup_args da;
	struct dedup_config *dc;
	struct workqueue_struct *wq;

	struct init_param_inram iparam_inram;
	struct init_param_cowbtree iparam_cowbtree;
	void *iparam;
	struct metadata *md = NULL;

	uint64_t data_size;
	int r;
	int crypto_key_size;

	struct on_disk_stats *data = NULL;
	uint64_t logical_block_counter = 0;
	uint64_t physical_block_counter = 0;

	uint32_t flushrq = 0;
	mempool_t *dedup_work_pool = NULL;

	bool unformatted;

	memset(&da, 0, sizeof(struct dedup_args));
	da.ti = ti;

	r = parse_dedup_args(&da, argc, argv, &ti->error);
	if (r)
		goto out;

	dc = kzalloc(sizeof(*dc), GFP_KERNEL);
	if (!dc) {
		ti->error = "Error allocating memory for dedup config";
		r = -ENOMEM;
		goto out;
	}

	wq = create_singlethread_workqueue("dm-dedup");
	if (!wq) {
		ti->error = "failed to create workqueue";
		r = -ENOMEM;
		goto bad_wq;
	}

	dedup_work_pool = mempool_create_kmalloc_pool(MIN_DEDUP_WORK_IO,
						sizeof(struct dedup_work));
	if (!dedup_work_pool) {
		r = -ENOMEM;
		ti->error = "failed to create mempool";
		goto bad_mempool;
	}

	dc->io_client = dm_io_client_create();
	if (IS_ERR(dc->io_client)) {
		r = PTR_ERR(dc->io_client);
		ti->error = "failed to create dm_io_client";
		goto bad_io_client;
	}

	dc->block_size = da.block_size;
	dc->sectors_per_block = to_sector(da.block_size);
	dc->lblocks = ti->len / dc->sectors_per_block;

	data_size = i_size_read(da.data_dev->bdev->bd_inode);
	dc->pblocks = data_size / da.block_size;

	/* Meta-data backend specific part */
	if (da.backend == BKND_INRAM) {
		dc->mdops = &metadata_ops_inram;
		iparam_inram.blocks = dc->pblocks;
		iparam = &iparam_inram;
	} else if (da.backend == BKND_COWBTREE) {
		r = -EINVAL;
		dc->mdops = &metadata_ops_cowbtree;
		iparam_cowbtree.blocks = dc->pblocks;
		iparam_cowbtree.metadata_bdev = da.meta_dev->bdev;
		iparam = &iparam_cowbtree;
	} else
		BUG();

	md = dc->mdops->init_meta(iparam, &unformatted);
	if (IS_ERR(md)) {
		ti->error = "failed to initialize backend metadata";
		r = PTR_ERR(md);
		goto bad_metadata_init;
	}

	dc->desc_table = desc_table_init(da.hash_algo);
	if (!dc->desc_table || IS_ERR(dc->desc_table)) {
		ti->error = "failed to initialize crypto API";
		r = PTR_ERR(dc->desc_table);
		goto bad_metadata_init;
	}

	crypto_key_size = get_hash_digestsize(dc->desc_table);

	dc->kvs_hash_pbn = dc->mdops->kvs_create_sparse(md, crypto_key_size,
				sizeof(struct hash_pbn_value),
				dc->pblocks, unformatted);
	if (IS_ERR(dc->kvs_hash_pbn)) {
		r = PTR_ERR(dc->kvs_hash_pbn);
		ti->error = "failed to create sparse KVS";
		goto bad_kvstore_init;
	}

	dc->kvs_lbn_pbn = dc->mdops->kvs_create_linear(md, 8,
			sizeof(struct lbn_pbn_value), dc->lblocks, unformatted);
	if (IS_ERR(dc->kvs_lbn_pbn)) {
		ti->error = "failed to create linear KVS";
		r = PTR_ERR(dc->kvs_lbn_pbn);
		goto bad_kvstore_init;
	}

	r = dc->mdops->flush_meta(md);
	if (r < 0)
		BUG();

	if (!unformatted && dc->mdops->get_private_data) {
		r = dc->mdops->get_private_data(md, (void **)&data,
				sizeof(struct on_disk_stats));
		if (r < 0)
			BUG();

		logical_block_counter = data->logical_block_counter;
		physical_block_counter = data->physical_block_counter;
	}

	dc->data_dev = da.data_dev;
	dc->metadata_dev = da.meta_dev;

	dc->workqueue = wq;
	dc->dedup_work_pool = dedup_work_pool;
	dc->bmd = md;

	dc->logical_block_counter = logical_block_counter;
	dc->physical_block_counter = physical_block_counter;

	dc->writes = 0;
	dc->dupwrites = 0;
	dc->uniqwrites = 0;
	dc->reads_on_writes = 0;
	dc->overwrites = 0;
	dc->newwrites = 0;

	strcpy(dc->crypto_alg, da.hash_algo);
	dc->crypto_key_size = crypto_key_size;

	dc->flushrq = flushrq;
	dc->writes_after_flush = 0;

	r = dm_set_target_max_io_len(ti, dc->sectors_per_block);
	if (r)
		goto bad_kvstore_init;

	ti->private = dc;

	return 0;

bad_kvstore_init:
	desc_table_deinit(dc->desc_table);
bad_metadata_init:
	if (md && !IS_ERR(md))
		dc->mdops->exit_meta(md);
	dm_io_client_destroy(dc->io_client);
bad_io_client:
	mempool_destroy(dedup_work_pool);
bad_mempool:
	destroy_workqueue(wq);
bad_wq:
	kfree(dc);
out:
	destroy_dedup_args(&da);
	return r;
}

static void dm_dedup_dtr(struct dm_target *ti)
{
	struct dedup_config *dc = ti->private;
	struct on_disk_stats data;
	int ret;

	if (dc->mdops->set_private_data) {
		data.physical_block_counter = dc->physical_block_counter;
		data.logical_block_counter = dc->logical_block_counter;

		ret = dc->mdops->set_private_data(dc->bmd, &data,
				sizeof(struct on_disk_stats));
		if (ret < 0)
			BUG();
	}

	ret = dc->mdops->flush_meta(dc->bmd);
	if (ret < 0)
		BUG();

	flush_workqueue(dc->workqueue);
	destroy_workqueue(dc->workqueue);

	mempool_destroy(dc->dedup_work_pool);

	dc->mdops->exit_meta(dc->bmd);

	dm_io_client_destroy(dc->io_client);

	dm_put_device(ti, dc->data_dev);
	dm_put_device(ti, dc->metadata_dev);
	desc_table_deinit(dc->desc_table);

	kfree(dc);
}

static void dm_dedup_status(struct dm_target *ti, status_type_t status_type,
			    unsigned status_flags, char *result, unsigned maxlen)
{
	struct dedup_config *dc = ti->private;
	uint64_t data_total_block_count;
	uint64_t data_used_block_count;
	uint64_t data_free_block_count;
	uint64_t data_actual_block_count;
	int sz = 0;

	switch (status_type) {
	case STATUSTYPE_INFO:
	case STATUSTYPE_TABLE:
		data_used_block_count = dc->physical_block_counter;
		data_actual_block_count = dc->logical_block_counter;
		data_total_block_count = dc->pblocks;

		data_free_block_count =
			data_total_block_count - data_used_block_count;

		DMEMIT("%llu %llu %llu %llu ",
			data_total_block_count, data_free_block_count,
			data_used_block_count, data_actual_block_count);

		DMEMIT("%u %s %s ", dc->block_size,
			dc->data_dev->name, dc->metadata_dev->name);

		DMEMIT("%llu %llu %llu %llu %llu %llu",
			dc->writes, dc->uniqwrites, dc->dupwrites,
			dc->reads_on_writes, dc->overwrites, dc->newwrites);
	}
}

static int mark_lbn_pbn_bitmap(void *key, int32_t ksize,
			       void *value, int32_t vsize, void *data)
{
	int ret = 0;
	struct mark_and_sweep_data *ms_data =
		(struct mark_and_sweep_data *)data;
	uint64_t pbn_val = *((uint64_t *)value);

	BUG_ON(!data);
	BUG_ON(!ms_data->bitmap);
	BUG_ON(pbn_val > ms_data->bitmap_len);

	bitmap_set(ms_data->bitmap, pbn_val, 1);

	return ret;
}

static int cleanup_hash_pbn(void *key, int32_t ksize, void *value,
			    int32_t vsize, void *data)
{
	int ret = 0, r = 0;
	uint64_t pbn_val = 0;
	struct mark_and_sweep_data *ms_data =
		(struct mark_and_sweep_data *)data;
	struct hash_pbn_value hashpbn_value = *((struct hash_pbn_value *)value);
	struct dedup_config *dc = ms_data->dc;

	BUG_ON(!data);
	BUG_ON(!ms_data->bitmap);

	pbn_val = hashpbn_value.pbn;
	BUG_ON(pbn_val > ms_data->bitmap_len);

	if (test_bit(pbn_val, ms_data->bitmap) == 0) {
		ret = dc->kvs_hash_pbn->kvs_delete(dc->kvs_hash_pbn,
							key, ksize);
		if (ret < 0)
			BUG();

		r = dc->mdops->dec_refcount(ms_data->dc->bmd, pbn_val);
		if (r < 0)
			BUG();

		ms_data->cleanup_count++;
	}

	return ret;
}

/*
 * Creates a bitmap of all PBNs in use by walking through
 * kvs_lbn_pbn. Then walks through kvs_hash_pbn and deletes
 * any entries which do not have an lbn-to-pbn mapping.
 */
static int mark_and_sweep(struct dedup_config *dc)
{
	int err = 0;
	uint64_t data_size = 0;
	uint64_t bitmap_size = 0;
	struct mark_and_sweep_data ms_data;

	BUG_ON(!dc);

	data_size = i_size_read(dc->data_dev->bdev->bd_inode);
	bitmap_size = data_size / dc->block_size;

	memset(&ms_data, 0, sizeof(struct mark_and_sweep_data));

	ms_data.bitmap = vmalloc(BITS_TO_LONGS(bitmap_size) *
			sizeof(unsigned long));
	if (!ms_data.bitmap) {
		DMERR("Could not vmalloc ms_data.bitmap");
		err = -ENOMEM;
		goto out;
	}
	bitmap_zero(ms_data.bitmap, bitmap_size);

	ms_data.bitmap_len = bitmap_size;
	ms_data.cleanup_count = 0;
	ms_data.dc = dc;

	/* Create bitmap of used pbn blocks */
	err = dc->kvs_lbn_pbn->kvs_iterate(dc->kvs_lbn_pbn,
			&mark_lbn_pbn_bitmap, (void *)&ms_data);
	if (err < 0)
		goto out_free;

	/* Cleanup hashes based on above bitmap of used pbn blocks */
	err = dc->kvs_hash_pbn->kvs_iterate(dc->kvs_hash_pbn,
			&cleanup_hash_pbn, (void *)&ms_data);
	if (err < 0)
		goto out_free;

	dc->physical_block_counter -= ms_data.cleanup_count;

out_free:
	vfree(ms_data.bitmap);
out:
	return err;
}

static int dm_dedup_message(struct dm_target *ti,
			    unsigned argc, char **argv)
{
	int r = 0;

	struct dedup_config *dc = ti->private;

	if (!strcasecmp(argv[0], "mark_and_sweep")) {
		r = mark_and_sweep(dc);
		if (r < 0)
			DMERR("Error in performing mark_and_sweep: %d.", r);
	} else if (!strcasecmp(argv[0], "drop_bufio_cache")) {
		if (dc->mdops->flush_bufio_cache)
			dc->mdops->flush_bufio_cache(dc->bmd);
		else
			r = -ENOTSUPP;
	} else
		r = -EINVAL;

	return r;
}

static int dm_dedup_endio(struct dm_target *ti, struct bio *bio, int error)
{
	if (error || bio_data_dir(bio) != READ)
		return 0;

	return 0;
}

static struct target_type dm_dedup_target = {
	.name = "dedup",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = dm_dedup_ctr,
	.dtr = dm_dedup_dtr,
	.map = dm_dedup_map,
	.end_io = dm_dedup_endio,
	.message = dm_dedup_message,
	.status = dm_dedup_status,
};

static int __init dm_dedup_init(void)
{
	int r;

	r = dm_register_target(&dm_dedup_target);
	if (r)
		return r;

	return 0;
}

static void __exit dm_dedup_exit(void)
{
	dm_unregister_target(&dm_dedup_target);
}

module_init(dm_dedup_init);
module_exit(dm_dedup_exit);

MODULE_DESCRIPTION(DM_NAME " target for data deduplication");
MODULE_LICENSE("GPL");

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

<<<<<<< HEAD
#include <linux/atomic.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/memblock.h>
=======
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
#include <linux/miscdevice.h>
#include <linux/msm_ion.h>
#include <linux/uaccess.h>
#include "compat_ion.h"
#include "ion_priv.h"

struct ion_device {
	struct miscdevice dev;
	struct plist_head heaps;
	struct rw_semaphore heap_rwsem;
	long (*custom_ioctl)(struct ion_client *client, unsigned int cmd,
			     unsigned long arg);
};

struct ion_client {
	struct ion_device *idev;
	struct idr handle_idr;
	struct rb_root handle_root;
	rwlock_t idr_lock;
	rwlock_t rb_lock;
};

<<<<<<< HEAD
<<<<<<< HEAD
=======
static struct ion_device *ion_dev;

>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
bool ion_buffer_fault_user_mappings(struct ion_buffer *buffer)
{
	return (buffer->flags & ION_FLAG_CACHED) &&
		!(buffer->flags & ION_FLAG_CACHED_NEEDS_SYNC);
}

bool ion_buffer_cached(struct ion_buffer *buffer)
{
	return !!(buffer->flags & ION_FLAG_CACHED);
}

static inline struct page *ion_buffer_page(struct page *page)
{
	return (struct page *)((unsigned long)page & ~(1UL));
}

static inline bool ion_buffer_page_is_dirty(struct page *page)
{
	return !!((unsigned long)page & 1UL);
}

static inline void ion_buffer_page_dirty(struct page **page)
=======
static void ion_buffer_free_work(struct work_struct *work)
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
{
	struct ion_buffer *buffer = container_of(work, typeof(*buffer), free);
	struct ion_heap *heap = buffer->heap;

	msm_dma_buf_freed(&buffer->iommu_data);
	if (buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	heap->ops->unmap_dma(heap, buffer);
	heap->ops->free(buffer);
	kfree(buffer);
}

<<<<<<< HEAD
/* this function should only be called while dev->lock is held */
static struct ion_buffer *ion_buffer_create(struct ion_heap *heap,
				     struct ion_device *dev,
				     const char *alloc_client_name,
				     unsigned long len,
				     unsigned long align,
				     unsigned long flags)
=======
static struct ion_buffer *ion_buffer_create(struct ion_heap *heap, size_t len,
					    size_t align, unsigned int flags)
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
{
	struct ion_buffer *buffer;
	struct scatterlist *sg;
	unsigned int i;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.flags = flags,
		.heap = heap,
		.size = len,
		.refcount = ATOMIC_INIT(1),
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.free = __WORK_INITIALIZER(buffer->free, ion_buffer_free_work),
		.iommu_data = {
			.map_list = LIST_HEAD_INIT(buffer->iommu_data.map_list),
			.lock = __MUTEX_INITIALIZER(buffer->iommu_data.lock)
		}
	};

	if (heap->ops->allocate(heap, buffer, len, align, flags)) {
		if (!(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

<<<<<<< HEAD
	buffer->dev = dev;
	buffer->size = len;
	buffer->flags = flags;
	INIT_LIST_HEAD(&buffer->vmas);

	snprintf(buffer->alloc_client_name, ION_ALLOC_CLIENT_NAME_SIZE,
		"%s", alloc_client_name);

	table = heap->ops->map_dma(heap, buffer);
	if (WARN_ONCE(table == NULL,
			"heap->ops->map_dma should return ERR_PTR on error"))
		table = ERR_PTR(-EINVAL);
	if (IS_ERR(table)) {
		ret = -EINVAL;
		goto err1;
=======
		drain_workqueue(heap->wq);
		if (heap->ops->allocate(heap, buffer, len, align, flags))
			goto free_buffer;
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
	}

	buffer->sg_table = heap->ops->map_dma(heap, buffer);
	if (IS_ERR_OR_NULL(buffer->sg_table))
		goto free_heap;

	for_each_sg(buffer->sg_table->sgl, sg, buffer->sg_table->nents, i) {
		sg_dma_address(sg) = sg_phys(sg);
		sg_dma_len(sg) = sg->length;
	}
<<<<<<< HEAD
	mutex_lock(&dev->buffer_lock);
	ion_buffer_add(dev, buffer);
	mutex_unlock(&dev->buffer_lock);
<<<<<<< HEAD
	atomic_long_add(len, &heap->total_allocated);
=======

>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
=======
	trace_ion_heap_grow(heap->name, len,
			    atomic_read(&heap->total_allocated));
	atomic_add(len, &heap->total_allocated);
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
	return buffer;

free_heap:
	heap->ops->free(buffer);
<<<<<<< HEAD
err2:
	kfree(buffer);
	return ERR_PTR(ret);
}

void ion_buffer_destroy(struct ion_buffer *buffer)
{
	if (WARN_ON(buffer->kmap_cnt > 0))
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	buffer->heap->ops->unmap_dma(buffer->heap, buffer);

	trace_ion_heap_shrink(buffer->heap->name,  buffer->size,
			      atomic_read(&buffer->heap->total_allocated));
	atomic_sub(buffer->size, &buffer->heap->total_allocated);
	buffer->heap->ops->free(buffer);
	vfree(buffer->pages);
=======
free_buffer:
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
	kfree(buffer);
	return ERR_PTR(-EINVAL);
}

void ion_buffer_put(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
<<<<<<< HEAD
	struct ion_device *dev = buffer->dev;

	msm_dma_buf_freed(&buffer->iommu_data);

	mutex_lock(&dev->buffer_lock);
	rb_erase(&buffer->node, &dev->buffers);
	mutex_unlock(&dev->buffer_lock);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_freelist_add(heap, buffer);
	else
		ion_buffer_destroy(buffer);
}

static void ion_buffer_get(struct ion_buffer *buffer)
{
	kref_get(&buffer->ref);
}

static int ion_buffer_put(struct ion_buffer *buffer)
{
	return kref_put(&buffer->ref, _ion_buffer_destroy);
}

static void ion_buffer_add_to_handle(struct ion_buffer *buffer)
{
	mutex_lock(&buffer->lock);
	if (buffer->handle_count == 0)
		atomic_add(buffer->size, &buffer->heap->total_handles);

	buffer->handle_count++;
	mutex_unlock(&buffer->lock);
}

static void ion_buffer_remove_from_handle(struct ion_buffer *buffer)
{
	/*
	 * when a buffer is removed from a handle, if it is not in
	 * any other handles, copy the taskcomm and the pid of the
	 * process it's being removed from into the buffer.  At this
	 * point there will be no way to track what processes this buffer is
	 * being used by, it only exists as a dma_buf file descriptor.
	 * The taskcomm and pid can provide a debug hint as to where this fd
	 * is in the system
	 */
	mutex_lock(&buffer->lock);
	buffer->handle_count--;
	BUG_ON(buffer->handle_count < 0);
	if (!buffer->handle_count) {
		struct task_struct *task;

		task = current->group_leader;
		get_task_comm(buffer->task_comm, task);
		buffer->pid = task_pid_nr(task);
<<<<<<< HEAD
		atomic_long_sub(buffer->size, &buffer->heap->total_handles);
=======

	if (atomic_dec_and_test(&buffer->refcount)) {
		if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
			queue_work(heap->wq, &buffer->free);
		else
			ion_buffer_free_work(&buffer->free);
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
=======
		atomic_sub(buffer->size, &buffer->heap->total_handles);
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
	}
}

static struct ion_handle *ion_handle_create(struct ion_client *client,
					    struct ion_buffer *buffer)
{
	struct ion_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);
<<<<<<< HEAD
	kref_init(&handle->ref);
	RB_CLEAR_NODE(&handle->node);
	handle->client = client;
	ion_buffer_get(buffer);
	ion_buffer_add_to_handle(buffer);
	handle->buffer = buffer;

	return handle;
}

static void ion_handle_kmap_put(struct ion_handle *);

static void ion_handle_destroy(struct kref *kref)
{
	struct ion_handle *handle = container_of(kref, struct ion_handle, ref);
	struct ion_client *client = handle->client;
	struct ion_buffer *buffer = handle->buffer;

	mutex_lock(&buffer->lock);
	while (handle->kmap_cnt)
		ion_handle_kmap_put(handle);
	mutex_unlock(&buffer->lock);

	idr_remove(&client->idr, handle->id);
	if (!RB_EMPTY_NODE(&handle->node))
		rb_erase(&handle->node, &client->handles);

	ion_buffer_remove_from_handle(buffer);
	ion_buffer_put(buffer);

	kfree(handle);
}

struct ion_buffer *ion_handle_buffer(struct ion_handle *handle)
{
	return handle->buffer;
}

static void ion_handle_get(struct ion_handle *handle)
{
	kref_get(&handle->ref);
}

/* Must hold the client lock */
static struct ion_handle *ion_handle_get_check_overflow(
					struct ion_handle *handle)
{
	if (atomic_read(&handle->ref.refcount) + 1 == 0)
		return ERR_PTR(-EOVERFLOW);
	ion_handle_get(handle);
	return handle;
}

static int ion_handle_put_nolock(struct ion_handle *handle)
{
	int ret;

	ret = kref_put(&handle->ref, ion_handle_destroy);

	return ret;
}

int ion_handle_put(struct ion_handle *handle)
{
	struct ion_client *client = handle->client;
	int ret;

	mutex_lock(&client->lock);
	ret = ion_handle_put_nolock(handle);
	mutex_unlock(&client->lock);

	return ret;
}

/* Must hold the client lock */
static void user_ion_handle_get(struct ion_handle *handle)
{
	if (handle->user_ref_count++ == 0)
		kref_get(&handle->ref);
}

/* Must hold the client lock */
static struct ion_handle *user_ion_handle_get_check_overflow(struct ion_handle *handle)
{
	if (handle->user_ref_count + 1 == 0)
		return ERR_PTR(-EOVERFLOW);
	user_ion_handle_get(handle);
	return handle;
}

/* passes a kref to the user ref count.
 * We know we're holding a kref to the object before and
 * after this call, so no need to reverify handle. */
static struct ion_handle *pass_to_user(struct ion_handle *handle)
{
	struct ion_client *client = handle->client;
	struct ion_handle *ret;

	mutex_lock(&client->lock);
	ret = user_ion_handle_get_check_overflow(handle);
	ion_handle_put_nolock(handle);
	mutex_unlock(&client->lock);
	return ret;
}

/* Must hold the client lock */
static int user_ion_handle_put_nolock(struct ion_handle *handle)
{
	int ret = 0;

	if (--handle->user_ref_count == 0)
		ret = ion_handle_put_nolock(handle);

	return ret;
}

static struct ion_handle *ion_handle_lookup(struct ion_client *client,
					    struct ion_buffer *buffer)
{
	struct rb_node *n = client->handles.rb_node;

	while (n) {
		struct ion_handle *entry = rb_entry(n, struct ion_handle, node);

		if (buffer < entry->buffer)
			n = n->rb_left;
		else if (buffer > entry->buffer)
			n = n->rb_right;
		else
			return entry;
	}
	return ERR_PTR(-EINVAL);
}

struct ion_handle *ion_handle_get_by_id_nolock(struct ion_client *client,
					       int id)
{
	struct ion_handle *handle;

	handle = idr_find(&client->idr, id);
	if (handle)
		return ion_handle_get_check_overflow(handle);

	return ERR_PTR(-EINVAL);
}

bool ion_handle_validate(struct ion_client *client, struct ion_handle *handle)
{
	WARN_ON(!mutex_is_locked(&client->lock));
	return idr_find(&client->idr, handle->id) == handle;
}

static int ion_handle_add(struct ion_client *client, struct ion_handle *handle)
{
	int id;
	struct rb_node **p = &client->handles.rb_node;
	struct rb_node *parent = NULL;
	struct ion_handle *entry;

	id = idr_alloc(&client->idr, handle, 1, 0, GFP_KERNEL);
	if (id < 0)
		return id;

	handle->id = id;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct ion_handle, node);

		if (handle->buffer < entry->buffer)
			p = &(*p)->rb_left;
		else if (handle->buffer > entry->buffer)
			p = &(*p)->rb_right;
		else
			WARN(1, "%s: buffer already found.", __func__);
	}

	rb_link_node(&handle->node, parent, p);
	rb_insert_color(&handle->node, &client->handles);

	return 0;
}

static struct ion_handle *__ion_alloc(struct ion_client *client, size_t len,
			     size_t align, unsigned int heap_id_mask,
			     unsigned int flags, bool grab_handle)
{
	struct ion_handle *handle;
	struct ion_device *dev = client->dev;
	struct ion_buffer *buffer = NULL;
	struct ion_heap *heap;
	int ret;
	const unsigned int MAX_DBG_STR_LEN = 64;
	char dbg_str[MAX_DBG_STR_LEN];
	unsigned int dbg_str_idx = 0;

	dbg_str[0] = '\0';

	/*
	 * For now, we don't want to fault in pages individually since
	 * clients are already doing manual cache maintenance. In
	 * other words, the implicit caching infrastructure is in
	 * place (in code) but should not be used.
	 */
	flags |= ION_FLAG_CACHED_NEEDS_SYNC;

	pr_debug("%s: len %zu align %zu heap_id_mask %u flags %x\n", __func__,
		 len, align, heap_id_mask, flags);
	/*
	 * traverse the list of heaps available in this system in priority
	 * order.  If the heap type is supported by the client, and matches the
	 * request of the caller allocate from it.  Repeat until allocate has
	 * succeeded or all heaps have been tried
	 */
	len = PAGE_ALIGN(len);

	if (!len)
		return ERR_PTR(-EINVAL);

	down_read(&dev->lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		/* if the caller didn't specify this heap id */
		if (!((1 << heap->id) & heap_id_mask))
			continue;
		trace_ion_alloc_buffer_start(client->name, heap->name, len,
					     heap_id_mask, flags);
		buffer = ion_buffer_create(heap, dev,
					   client->name, len, align, flags);
		trace_ion_alloc_buffer_end(client->name, heap->name, len,
					   heap_id_mask, flags);
		if (!IS_ERR(buffer))
			break;

		trace_ion_alloc_buffer_fallback(client->name, heap->name, len,
					    heap_id_mask, flags,
					    PTR_ERR(buffer));
		if (dbg_str_idx < MAX_DBG_STR_LEN) {
			unsigned int len_left = MAX_DBG_STR_LEN-dbg_str_idx-1;
			int ret_value = snprintf(&dbg_str[dbg_str_idx],
						len_left, "%s ", heap->name);
			if (ret_value >= len_left) {
				/* overflow */
				dbg_str[MAX_DBG_STR_LEN-1] = '\0';
				dbg_str_idx = MAX_DBG_STR_LEN;
			} else if (ret_value >= 0) {
				dbg_str_idx += ret_value;
			} else {
				/* error */
				dbg_str[MAX_DBG_STR_LEN-1] = '\0';
			}
		}
	}
	up_read(&dev->lock);

	if (buffer == NULL) {
		trace_ion_alloc_buffer_fail(client->name, dbg_str, len,
					    heap_id_mask, flags, -ENODEV);
		return ERR_PTR(-ENODEV);
	}

	if (IS_ERR(buffer)) {
		trace_ion_alloc_buffer_fail(client->name, dbg_str, len,
					    heap_id_mask, flags,
					    PTR_ERR(buffer));
		pr_debug("ION is unable to allocate 0x%zx bytes (alignment: 0x%zx) from heap(s) %sfor client %s\n",
			len, align, dbg_str, client->name);
		return ERR_CAST(buffer);
	}

	handle = ion_handle_create(client, buffer);

	/*
	 * ion_buffer_create will create a buffer with a ref_cnt of 1,
	 * and ion_handle_create will take a second reference, drop one here
	 */
	ion_buffer_put(buffer);

	if (IS_ERR(handle))
		return handle;

	mutex_lock(&client->lock);
	if (grab_handle)
		ion_handle_get(handle);
	ret = ion_handle_add(client, handle);
	mutex_unlock(&client->lock);
	if (ret) {
		ion_handle_put(handle);
		handle = ERR_PTR(ret);
=======

	*handle = (typeof(*handle)){
		.buffer = buffer,
		.client = client,
		.refcount = ATOMIC_INIT(1)
	};

	idr_preload(GFP_KERNEL);
	write_lock(&client->idr_lock);
	handle->id = idr_alloc(&client->handle_idr, handle, 1, 0, GFP_ATOMIC);
	write_unlock(&client->idr_lock);
	idr_preload_end();
	if (handle->id < 0) {
		kfree(handle);
		return ERR_PTR(-ENOMEM);
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
	}

	RB_CLEAR_NODE(&handle->rnode);
	return handle;
}

<<<<<<< HEAD
struct ion_handle *ion_alloc(struct ion_client *client, size_t len,
			     size_t align, unsigned int heap_id_mask,
			     unsigned int flags)
{
	return __ion_alloc(client, len, align, heap_id_mask, flags, false);
}
EXPORT_SYMBOL(ion_alloc);

void ion_free_nolock(struct ion_client *client, struct ion_handle *handle)
{
	bool valid_handle;

	BUG_ON(client != handle->client);

	valid_handle = ion_handle_validate(client, handle);
	if (!valid_handle) {
		WARN(1, "%s: invalid handle passed to free.\n", __func__);
		return;
	}
	ion_handle_put_nolock(handle);
}

/* Must hold the client lock */
static void user_ion_free_nolock(struct ion_client *client, struct ion_handle *handle)
{
	bool valid_handle;

	BUG_ON(client != handle->client);

	valid_handle = ion_handle_validate(client, handle);
	if (!valid_handle) {
		WARN(1, "%s: invalid handle passed to free.\n", __func__);
		return;
	}
	if (handle->user_ref_count == 0) {
		WARN(1, "%s: User does not have access!\n", __func__);
		return;
	}
	user_ion_handle_put_nolock(handle);
}

void ion_free(struct ion_client *client, struct ion_handle *handle)
{
	BUG_ON(client != handle->client);

	mutex_lock(&client->lock);
	ion_free_nolock(client, handle);
	mutex_unlock(&client->lock);
}
EXPORT_SYMBOL(ion_free);

static int __ion_phys(struct ion_client *client, struct ion_handle *handle,
		      ion_phys_addr_t *addr, size_t *len, bool lock_client)
{
	struct ion_buffer *buffer;
	int ret;

	if (lock_client)
		mutex_lock(&client->lock);
	if (!ion_handle_validate(client, handle)) {
		if (lock_client)
			mutex_unlock(&client->lock);
		return -EINVAL;
	}

	buffer = handle->buffer;

	if (!buffer->heap->ops->phys) {
		pr_err("%s: ion_phys is not implemented by this heap (name=%s, type=%d).\n",
			__func__, buffer->heap->name, buffer->heap->type);
		if (lock_client)
			mutex_unlock(&client->lock);
		return -ENODEV;
	}
	if (lock_client)
		mutex_unlock(&client->lock);
	ret = buffer->heap->ops->phys(buffer->heap, buffer, addr, len);
	return ret;
}

int ion_phys(struct ion_client *client, struct ion_handle *handle,
	     ion_phys_addr_t *addr, size_t *len)
{
	return __ion_phys(client, handle, addr, len, true);
}
EXPORT_SYMBOL(ion_phys);

int ion_phys_nolock(struct ion_client *client, struct ion_handle *handle,
		    ion_phys_addr_t *addr, size_t *len)
{
	return __ion_phys(client, handle, addr, len, false);
}

static void *ion_buffer_kmap_get(struct ion_buffer *buffer)
{
	void *vaddr;

	if (buffer->kmap_cnt) {
		buffer->kmap_cnt++;
		return buffer->vaddr;
	}
	vaddr = buffer->heap->ops->map_kernel(buffer->heap, buffer);
	if (WARN_ONCE(vaddr == NULL,
			"heap->ops->map_kernel should return ERR_PTR on error"))
		return ERR_PTR(-EINVAL);
	if (IS_ERR(vaddr))
		return vaddr;
	buffer->vaddr = vaddr;
	buffer->kmap_cnt++;
	return vaddr;
}

static void *ion_handle_kmap_get(struct ion_handle *handle)
=======
void ion_handle_put(struct ion_handle *handle, int count)
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
{
	struct ion_buffer *buffer = handle->buffer;
	struct ion_client *client = handle->client;
	bool do_free;

	write_lock(&client->rb_lock);
	write_lock(&client->idr_lock);
	do_free = !atomic_sub_return(count, &handle->refcount);
	if (do_free) {
		idr_remove(&client->handle_idr, handle->id);
		if (!RB_EMPTY_NODE(&handle->rnode))
			rb_erase(&handle->rnode, &client->handle_root);
	}
	write_unlock(&client->idr_lock);
	write_unlock(&client->rb_lock);

	if (do_free) {
		ion_buffer_put(buffer);
		kfree(handle);
	}
}

void *__ion_map_kernel(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	void *vaddr;

	if (!heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);
<<<<<<< HEAD
	}

	mutex_lock(&buffer->lock);
	vaddr = ion_handle_kmap_get(handle);
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);
	return vaddr;
}
EXPORT_SYMBOL(ion_map_kernel);

void ion_unmap_kernel(struct ion_client *client, struct ion_handle *handle)
{
	struct ion_buffer *buffer;

	mutex_lock(&client->lock);
	buffer = handle->buffer;
	mutex_lock(&buffer->lock);
	ion_handle_kmap_put(handle);
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);
}
EXPORT_SYMBOL(ion_unmap_kernel);

static int ion_debug_client_show(struct seq_file *s, void *unused)
{
	struct ion_client *client = s->private;
	struct rb_node *n, *cnode;
	bool found = false;

	down_write(&ion_dev->lock);

	if (!client || (client->dev != ion_dev)) {
		up_write(&ion_dev->lock);
		return -EINVAL;
	}

	cnode = rb_first(&ion_dev->clients);
	for ( ; cnode; cnode = rb_next(cnode)) {
		struct ion_client *c = rb_entry(cnode,
				struct ion_client, node);
		if (client == c) {
			found = true;
			break;
		}
	}

	if (!found) {
		up_write(&ion_dev->lock);
		return -EINVAL;
	}

	seq_printf(s, "%16.16s: %16.16s : %16.16s : %12.12s\n",
			"heap_name", "size_in_bytes", "handle refcount",
			"buffer");

	mutex_lock(&client->lock);
	for (n = rb_first(&client->handles); n; n = rb_next(n)) {
		struct ion_handle *handle = rb_entry(n, struct ion_handle,
						     node);

		seq_printf(s, "%16.16s: %16zx : %16d : %12pK",
				handle->buffer->heap->name,
				handle->buffer->size,
				atomic_read(&handle->ref.refcount),
				handle->buffer);

		seq_printf(s, "\n");
	}
	mutex_unlock(&client->lock);
	up_write(&ion_dev->lock);
	return 0;
}

static int ion_debug_client_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_client_show, inode->i_private);
}

static const struct file_operations debug_client_fops = {
	.open = ion_debug_client_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int ion_get_client_serial(const struct rb_root *root,
					const unsigned char *name)
{
	int serial = -1;
	struct rb_node *node;

	for (node = rb_first(root); node; node = rb_next(node)) {
		struct ion_client *client = rb_entry(node, struct ion_client,
						node);

		if (strcmp(client->name, name))
			continue;
		serial = max(serial, client->display_serial);
	}
	return serial + 1;
}

struct ion_client *ion_client_create(struct ion_device *dev,
				     const char *name)
{
	struct ion_client *client;
	struct task_struct *task;
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct ion_client *entry;
	pid_t pid;

	if (!name) {
		pr_err("%s: Name cannot be null\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	get_task_struct(current->group_leader);
	task_lock(current->group_leader);
	pid = task_pid_nr(current->group_leader);
	/*
	 * don't bother to store task struct for kernel threads,
	 * they can't be killed anyway
	 */
	if (current->group_leader->flags & PF_KTHREAD) {
		put_task_struct(current->group_leader);
		task = NULL;
=======

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_refcount) {
		vaddr = buffer->vaddr;
		buffer->kmap_refcount++;
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
	} else {
		vaddr = heap->ops->map_kernel(heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_refcount++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);

	return vaddr;
}

void __ion_unmap_kernel(struct ion_buffer *buffer)
{
<<<<<<< HEAD
	struct ion_device *dev = client->dev;
	struct rb_node *n;

	pr_debug("%s: %d\n", __func__, __LINE__);
	mutex_lock(&client->lock);
	while ((n = rb_first(&client->handles))) {
		struct ion_handle *handle = rb_entry(n, struct ion_handle,
						     node);
		ion_handle_destroy(&handle->ref);
	}

	idr_destroy(&client->idr);
	mutex_unlock(&client->lock);

	down_write(&dev->lock);
	if (client->task)
		put_task_struct(client->task);
	rb_erase(&client->node, &dev->clients);
	debugfs_remove_recursive(client->debug_root);

	up_write(&dev->lock);

	kfree(client->display_name);
	kfree(client->name);
	kfree(client);
<<<<<<< HEAD
	mutex_unlock(&debugfs_mutex);
=======
	struct ion_heap *heap = buffer->heap;
=======
}
EXPORT_SYMBOL(ion_client_destroy);

int ion_handle_get_flags(struct ion_client *client, struct ion_handle *handle,
			unsigned long *flags)
{
	struct ion_buffer *buffer;

	mutex_lock(&client->lock);
	if (!ion_handle_validate(client, handle)) {
		pr_err("%s: invalid handle passed to %s.\n",
		       __func__, __func__);
		mutex_unlock(&client->lock);
		return -EINVAL;
	}
	buffer = handle->buffer;
	mutex_lock(&buffer->lock);
	*flags = buffer->flags;
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);

	return 0;
}
EXPORT_SYMBOL(ion_handle_get_flags);

int ion_handle_get_size(struct ion_client *client, struct ion_handle *handle,
			size_t *size)
{
	struct ion_buffer *buffer;

	mutex_lock(&client->lock);
	if (!ion_handle_validate(client, handle)) {
		pr_err("%s: invalid handle passed to %s.\n",
		       __func__, __func__);
		mutex_unlock(&client->lock);
		return -EINVAL;
	}
	buffer = handle->buffer;
	mutex_lock(&buffer->lock);
	*size = buffer->size;
	mutex_unlock(&buffer->lock);
	mutex_unlock(&client->lock);
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo

	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
}

struct ion_buffer *__ion_alloc(struct ion_device *idev, size_t len,
			       size_t align, unsigned int heap_id_mask,
			       unsigned int flags)
{
	struct ion_buffer *buffer;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	down_read(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (BIT(heap->id) & heap_id_mask) {
			buffer = ion_buffer_create(heap, len, align, flags);
			if (!IS_ERR(buffer)) {
				up_read(&idev->heap_rwsem);
				return buffer;
			}
		}
	}
	up_read(&idev->heap_rwsem);

	return ERR_PTR(-EINVAL);
}

int __ion_phys(struct ion_buffer *buffer, ion_phys_addr_t *addr, size_t *len)
{
	struct ion_heap *heap = buffer->heap;

	if (!heap->ops->phys)
		return -ENODEV;

	return heap->ops->phys(heap, buffer, addr, len);
}

static struct sg_table *ion_dup_sg_table(struct sg_table *orig_table)
{
	unsigned int nents = orig_table->nents;
	struct scatterlist *sg_d, *sg_s;
	struct sg_table *table;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;

	if (sg_alloc_table(table, nents, GFP_KERNEL)) {
		kfree(table);
		return NULL;
	}

	for (sg_d = table->sgl, sg_s = orig_table->sgl;
	     nents > SG_MAX_SINGLE_ALLOC; nents -= SG_MAX_SINGLE_ALLOC - 1,
	     sg_d = sg_chain_ptr(&sg_d[SG_MAX_SINGLE_ALLOC - 1]),
	     sg_s = sg_chain_ptr(&sg_s[SG_MAX_SINGLE_ALLOC - 1]))
		memcpy(sg_d, sg_s, (SG_MAX_SINGLE_ALLOC - 1) * sizeof(*sg_d));

	if (nents)
		memcpy(sg_d, sg_s, nents * sizeof(*sg_d));

	return table;
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return ion_dup_sg_table(buffer->sg_table);
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction dir)
{
	sg_free_table(table);
	kfree(table);
}

<<<<<<< HEAD
void ion_pages_sync_for_device(struct device *dev, struct page *page,
		size_t size, enum dma_data_direction dir)
{
	struct scatterlist sg;

	WARN_ONCE(!dev, "A device is required for dma_sync\n");

	sg_init_table(&sg, 1);
	sg_set_page(&sg, page, size, 0);
	/*
	 * This is not correct - sg_dma_address needs a dma_addr_t that is valid
	 * for the targeted device, but this works on the currently targeted
	 * hardware.
	 */
	sg_dma_address(&sg) = page_to_phys(page);
	dma_sync_sg_for_device(dev, &sg, 1, dir);
}

struct ion_vma_list {
	struct list_head list;
	struct vm_area_struct *vma;
};

static void ion_buffer_sync_for_device(struct ion_buffer *buffer,
				       struct device *dev,
				       enum dma_data_direction dir)
{
	struct ion_vma_list *vma_list;
	int pages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	int i;

	pr_debug("%s: syncing for device %s\n", __func__,
		 dev ? dev_name(dev) : "null");

	if (!ion_buffer_fault_user_mappings(buffer))
		return;

	mutex_lock(&buffer->lock);
	for (i = 0; i < pages; i++) {
		struct page *page = buffer->pages[i];

		if (ion_buffer_page_is_dirty(page))
			ion_pages_sync_for_device(dev, ion_buffer_page(page),
							PAGE_SIZE, dir);

		ion_buffer_page_clean(buffer->pages + i);
	}
	list_for_each_entry(vma_list, &buffer->vmas, list) {
		struct vm_area_struct *vma = vma_list->vma;

		zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start,
			       NULL);
	}
	mutex_unlock(&buffer->lock);
}

static int ion_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	unsigned long pfn;
	int ret;

	mutex_lock(&buffer->lock);
	ion_buffer_page_dirty(buffer->pages + vmf->pgoff);
	BUG_ON(!buffer->pages || !buffer->pages[vmf->pgoff]);

	pfn = page_to_pfn(ion_buffer_page(buffer->pages[vmf->pgoff]));
	ret = vm_insert_pfn(vma, (unsigned long)vmf->virtual_address, pfn);
	mutex_unlock(&buffer->lock);
	if (ret)
		return VM_FAULT_ERROR;

	return VM_FAULT_NOPAGE;
}

static void ion_vm_open(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	vma_list = kmalloc(sizeof(struct ion_vma_list), GFP_KERNEL);
	if (!vma_list)
		return;
	vma_list->vma = vma;
	mutex_lock(&buffer->lock);
	list_add(&vma_list->list, &buffer->vmas);
	mutex_unlock(&buffer->lock);
	pr_debug("%s: adding %pK\n", __func__, vma);
}

static void ion_vm_close(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list, *tmp;

	pr_debug("%s\n", __func__);
	mutex_lock(&buffer->lock);
	list_for_each_entry_safe(vma_list, tmp, &buffer->vmas, list) {
		if (vma_list->vma != vma)
			continue;
		list_del(&vma_list->list);
		kfree(vma_list);
		pr_debug("%s: deleting %pK\n", __func__, vma);
		break;
	}
	mutex_unlock(&buffer->lock);

	if (buffer->heap->ops->unmap_user)
		buffer->heap->ops->unmap_user(buffer->heap, buffer);
}

static const struct vm_operations_struct ion_vma_ops = {
	.open = ion_vm_open,
	.close = ion_vm_close,
	.fault = ion_vm_fault,
};

=======
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	if (!heap->ops->map_user)
		return -EINVAL;

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return heap->ops->map_user(heap, buffer, vma);
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	ion_buffer_put(buffer);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return buffer->vaddr + offset * PAGE_SIZE;
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf, size_t start,
					size_t len, enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return PTR_RET(__ion_map_kernel(buffer));
}

static void ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf, size_t start,
				       size_t len, enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	__ion_unmap_kernel(buffer);
}

static const struct dma_buf_ops ion_dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.kmap_atomic = ion_dma_buf_kmap,
	.kmap = ion_dma_buf_kmap
};

struct dma_buf *__ion_share_dma_buf(struct ion_buffer *buffer)
{
	struct dma_buf_export_info exp_info = {
		.ops = &ion_dma_buf_ops,
		.size = buffer->size,
		.flags = O_RDWR,
		.priv = &buffer->iommu_data
	};
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_export(&exp_info);
	if (!IS_ERR(dmabuf))
		atomic_inc(&buffer->refcount);

	return dmabuf;
}

int __ion_share_dma_buf_fd(struct ion_buffer *buffer)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = __ion_share_dma_buf(buffer);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

<<<<<<< HEAD
<<<<<<< HEAD
bool ion_dma_buf_is_secure(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer;
	enum ion_heap_type type;

	/* Return false if we didn't create the buffer */
	if (!dmabuf || dmabuf->ops != &dma_buf_ops)
		return false;

	buffer = dmabuf->priv;

	if (!buffer || !buffer->heap)
		return false;

	type = buffer->heap->type;

	return (type == (enum ion_heap_type)ION_HEAP_TYPE_SECURE_DMA ||
		type == (enum ion_heap_type)ION_HEAP_TYPE_SYSTEM_SECURE) ?
		true : false;
}
EXPORT_SYMBOL(ion_dma_buf_is_secure);

=======
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
static int ion_share_dma_buf_fd_nolock(struct ion_client *client,
				       struct ion_handle *handle)
{
	return __ion_share_dma_buf_fd(client, handle, false);
=======
	return fd;
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
}

struct ion_buffer *__ion_import_dma_buf(int fd)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	buffer = container_of(dmabuf->priv, typeof(*buffer), iommu_data);
	atomic_inc(&buffer->refcount);
	dma_buf_put(dmabuf);
	return buffer;
}

struct ion_handle *ion_handle_get_by_id(struct ion_client *client, int id)
{
	struct ion_handle *handle;

	read_lock(&client->idr_lock);
	handle = idr_find(&client->handle_idr, id);
	if (handle)
		atomic_inc(&handle->refcount);
	read_unlock(&client->idr_lock);

	return handle ? handle : ERR_PTR(-EINVAL);
}

static void ion_handle_rb_add(struct ion_client *client,
			      struct ion_handle *handle)
{
	struct rb_node **p = &client->handle_root.rb_node;
	struct ion_buffer *buffer = handle->buffer;
	struct rb_node *parent = NULL;
	struct ion_handle *entry;

	write_lock(&client->rb_lock);
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, typeof(*entry), rnode);
		if (buffer < entry->buffer)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&handle->rnode, parent, p);
	rb_insert_color(&handle->rnode, &client->handle_root);
	write_unlock(&client->rb_lock);
}

static struct ion_handle *ion_handle_get_by_buffer(struct ion_client *client,
						   struct ion_buffer *buffer)
{
	struct rb_node **p = &client->handle_root.rb_node;
	struct ion_handle *entry;

	read_lock(&client->rb_lock);
	while (*p) {
		entry = rb_entry(*p, typeof(*entry), rnode);
		if (buffer < entry->buffer) {
			p = &(*p)->rb_left;
		} else if (buffer > entry->buffer) {
			p = &(*p)->rb_right;
		} else {
			atomic_inc(&entry->refcount);
			read_unlock(&client->rb_lock);
			return entry;
		}
	}
	read_unlock(&client->rb_lock);

	return ERR_PTR(-EINVAL);
}

static long ion_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	union {
		struct ion_fd_data fd;
		struct ion_allocation_data allocation;
		struct ion_handle_data handle;
		struct ion_custom_data custom;
	} data;
	struct ion_client *client = file->private_data;
	struct ion_device *idev = client->idev;
	struct ion_buffer *buffer;
	struct ion_handle *handle;
	struct dma_buf *dmabuf;
	int *output;

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	switch (cmd) {
	case ION_IOC_CUSTOM:
		if (!idev->custom_ioctl)
			return -ENOTTY;
	case ION_IOC_ALLOC:
	case ION_IOC_FREE:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
		buffer = __ion_alloc(idev, data.allocation.len,
				     data.allocation.align,
				     data.allocation.heap_id_mask,
				     data.allocation.flags);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

		handle = ion_handle_create(client, buffer);
		if (IS_ERR(handle)) {
			ion_buffer_put(buffer);
			return PTR_ERR(handle);
		}

		output = &handle->id;
		arg += offsetof(struct ion_allocation_data, handle);
		break;
	case ION_IOC_FREE:
		handle = ion_handle_get_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		ion_handle_put(handle, 2);
		return 0;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		handle = ion_handle_get_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.fd.fd = __ion_share_dma_buf_fd(handle->buffer);
		ion_handle_put(handle, 1);
		if (data.fd.fd < 0)
			return data.fd.fd;

		output = &data.fd.fd;
		arg += offsetof(struct ion_fd_data, fd);
		break;
	case ION_IOC_IMPORT:
		buffer = __ion_import_dma_buf(data.fd.fd);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

<<<<<<< HEAD
<<<<<<< HEAD
		mutex_lock(&client->lock);
		handle = ion_import_dma_buf_nolock(client, data.fd.fd);
=======
		handle = ion_handle_get_by_buffer(client, buffer);
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
=======
		handle = ion_import_dma_buf(client, data.fd.fd);
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
		if (IS_ERR(handle)) {
			handle = ion_handle_create(client, buffer);
			if (IS_ERR(handle)) {
				ion_buffer_put(buffer);
				return PTR_ERR(handle);
			}
			ion_handle_rb_add(client, handle);
		} else {
			ion_buffer_put(buffer);
		}
<<<<<<< HEAD
<<<<<<< HEAD
		mutex_unlock(&client->lock);
=======

		output = &handle->id;
		arg += offsetof(struct ion_handle_data, handle);
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
=======
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
		break;
	case ION_IOC_CUSTOM:
		return idev->custom_ioctl(client, data.custom.cmd,
					  data.custom.arg);
	default:
		return -ENOTTY;
	}

	if (copy_to_user((void __user *)arg, output, sizeof(*output))) {
		switch (cmd) {
		case ION_IOC_ALLOC:
		case ION_IOC_IMPORT:
			ion_handle_put(handle, 1);
			break;
		case ION_IOC_SHARE:
		case ION_IOC_MAP:
			dmabuf = dma_buf_get(data.fd.fd);
			dma_buf_put(dmabuf);
			dma_buf_put(dmabuf);
			break;
		}

		return -EFAULT;
	}

<<<<<<< HEAD
<<<<<<< HEAD
=======
	pr_debug("%s: %d\n", __func__, __LINE__);
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
	ion_client_destroy(client);
=======
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
	return 0;
}

static int ion_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
<<<<<<< HEAD
	struct ion_device *dev = container_of(miscdev, struct ion_device, dev);
	struct ion_client *client;
	char debug_name[64];

	pr_debug("%s: %d\n", __func__, __LINE__);
	snprintf(debug_name, 64, "%u", task_pid_nr(current->group_leader));
	client = ion_client_create(dev, debug_name);
	if (IS_ERR(client))
		return PTR_ERR(client);
	file->private_data = client;

	return 0;
}

static const struct file_operations ion_fops = {
	.owner          = THIS_MODULE,
	.open           = ion_open,
	.release        = ion_release,
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl   = compat_ion_ioctl,
};

static size_t ion_debug_heap_total(struct ion_client *client,
				   unsigned int id)
{
	size_t size = 0;
	struct rb_node *n;

	mutex_lock(&client->lock);
	for (n = rb_first(&client->handles); n; n = rb_next(n)) {
		struct ion_handle *handle = rb_entry(n,
						     struct ion_handle,
						     node);
		if (handle->buffer->heap->id == id)
			size += handle->buffer->size;
	}
	mutex_unlock(&client->lock);
	return size;
}

/**
 * Create a mem_map of the heap.
 * @param s seq_file to log error message to.
 * @param heap The heap to create mem_map for.
 * @param mem_map The mem map to be created.
 */
void ion_debug_mem_map_create(struct seq_file *s, struct ion_heap *heap,
			      struct list_head *mem_map)
{
	struct ion_device *dev = heap->dev;
	struct rb_node *cnode;
	size_t size;
=======
	struct ion_device *idev = container_of(miscdev, typeof(*idev), dev);
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
	struct ion_client *client;

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	*client = (typeof(*client)){
		.idev = idev,
		.handle_idr = IDR_INIT(client->handle_idr),
		.idr_lock = __RW_LOCK_UNLOCKED(client->idr_lock),
		.rb_lock = __RW_LOCK_UNLOCKED(client->rb_lock)
	};

	file->private_data = client;
	return 0;
}

static int ion_release(struct inode *inode, struct file *file)
{
	struct ion_client *client = file->private_data;
	struct ion_handle *handle;
	int id;

<<<<<<< HEAD
static int ion_debug_heap_show(struct seq_file *s, void *unused)
{
	struct ion_heap *heap = s->private;
	struct ion_device *dev = heap->dev;
	struct rb_node *n;
	size_t total_size = 0;
	size_t total_orphaned_size = 0;

	seq_printf(s, "%16s %16s %16s\n", "client", "pid", "size");
	seq_puts(s, "----------------------------------------------------\n");

	down_read(&dev->lock);
	for (n = rb_first(&dev->clients); n; n = rb_next(n)) {
		struct ion_client *client = rb_entry(n, struct ion_client,
						     node);
		size_t size = ion_debug_heap_total(client, heap->id);

		if (!size)
			continue;
		if (client->task) {
			char task_comm[TASK_COMM_LEN];

			get_task_comm(task_comm, client->task);
			seq_printf(s, "%16s %16u %16zu\n", task_comm,
				   client->pid, size);
		} else {
			seq_printf(s, "%16s %16u %16zu\n", client->name,
				   client->pid, size);
		}
	}
	up_read(&dev->lock);
	seq_puts(s, "----------------------------------------------------\n");
	seq_puts(s, "orphaned allocations (info is from last known client):\n");
	mutex_lock(&dev->buffer_lock);
	for (n = rb_first(&dev->buffers); n; n = rb_next(n)) {
		struct ion_buffer *buffer = rb_entry(n, struct ion_buffer,
						     node);
		if (buffer->heap->id != heap->id)
			continue;
		total_size += buffer->size;
		if (!buffer->handle_count) {
			seq_printf(s, "%16s %16u %16zu %d %d\n",
				   buffer->task_comm, buffer->pid,
				   buffer->size, buffer->kmap_cnt,
				   atomic_read(&buffer->ref.refcount));
			total_orphaned_size += buffer->size;
		}
=======
	idr_for_each_entry(&client->handle_idr, handle, id) {
		ion_buffer_put(handle->buffer);
		kfree(handle);
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
	}
	idr_destroy(&client->handle_idr);
	kfree(client);
	return 0;
}

static const struct file_operations ion_fops = {
	.open = ion_open,
	.release = ion_release,
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = compat_ion_ioctl
};

<<<<<<< HEAD
void show_ion_usage(struct ion_device *dev)
{
	struct ion_heap *heap;

	if (!down_read_trylock(&dev->lock)) {
		pr_err("Ion output would deadlock, can't print debug information\n");
		return;
	}

	pr_info("%16.s %16.s %16.s\n", "Heap name", "Total heap size",
					"Total orphaned size");
	pr_info("---------------------------------\n");
	plist_for_each_entry(heap, &dev->heaps, node) {
		pr_info("%16.s 0x%16.x 0x%16.x\n",
			heap->name, atomic_read(&heap->total_allocated),
			atomic_read(&heap->total_allocated) -
			atomic_read(&heap->total_handles));
		if (heap->debug_show)
			heap->debug_show(heap, NULL, 0);

	}
	up_read(&dev->lock);
}

#ifdef DEBUG_HEAP_SHRINKER
static int debug_shrink_set(void *data, u64 val)
=======
void ion_device_add_heap(struct ion_device *idev, struct ion_heap *heap)
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
{
	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE) {
		heap->wq = alloc_workqueue("%s", WQ_UNBOUND,
					   WQ_UNBOUND_MAX_ACTIVE, heap->name);
		BUG_ON(!heap->wq);
	}

	if (heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	plist_node_init(&heap->node, -heap->id);

	down_write(&idev->heap_rwsem);
	plist_add(&heap->node, &idev->heaps);
	up_write(&idev->heap_rwsem);
}

int ion_walk_heaps(struct ion_client *client, int heap_id,
		   enum ion_heap_type type, void *data,
		   int (*f)(struct ion_heap *heap, void *data))
{
	struct ion_device *idev = client->idev;
	struct ion_heap *heap;
	int ret = 0;

	down_write(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}
	up_write(&idev->heap_rwsem);

	return ret;
}

static int ion_debug_allbufs_show(struct seq_file *s, void *unused)
{
	struct ion_device *dev = s->private;
	struct rb_node *n;

	seq_printf(s, "%16.s %16.s %12.s %12.s %20.s    %s\n", "heap",
		"buffer", "size", "ref cnt", "allocator", "references");

	down_read(&dev->lock);
	mutex_lock(&dev->buffer_lock);
	for (n = rb_first(&dev->buffers); n; n = rb_next(n)) {
		struct rb_node *j;
		struct ion_buffer *buf = rb_entry(n, struct ion_buffer, node);
		int buf_refcount = atomic_read(&buf->ref.refcount);
		int refs_found = 0;
		int clients_busy = 0;

		seq_printf(s, "%16.s %16pK %12.x %12.d %20.s    %s",
			buf->heap->name, buf, (int)buf->size,
			buf_refcount, buf->alloc_client_name, "");

		for (j = rb_first(&dev->clients); j; j = rb_next(j)) {
			struct ion_client *entry = rb_entry(j,
							    struct ion_client,
							    node);
			struct ion_handle *handle;

			if (!mutex_trylock(&entry->lock)) {
				clients_busy++;
				continue;
			}
			handle = ion_handle_lookup(entry, buf);
			if (!IS_ERR(handle)) {
				seq_printf(s, "%s, ", entry->name);
				refs_found++;
			}
			mutex_unlock(&entry->lock);
		}
		if (refs_found != buf_refcount) {
			if ((buf_refcount == 1) && (!clients_busy))
				seq_printf(s, "orphaned_by: %d (%s)",
					buf->pid, buf->task_comm);
			else if (!clients_busy)
				seq_printf(s, "missing x %d",
					(buf_refcount-refs_found));
			else
				seq_puts(s,
					"!!!some clients were busy!!!");
		}

		seq_puts(s, "\n");
	}
	mutex_unlock(&dev->buffer_lock);
	up_read(&dev->lock);
	return 0;
}

static int ion_debug_allbufs_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_allbufs_show, inode->i_private);
}

static const struct file_operations debug_allbufs_fops = {
	.open = ion_debug_allbufs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

struct ion_device *ion_device_create(long (*custom_ioctl)
				     (struct ion_client *client,
				      unsigned int cmd, unsigned long arg))
{
	struct ion_device *idev;
	int ret;

	idev = kmalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev)
		return ERR_PTR(-ENOMEM);

	*idev = (typeof(*idev)){
		.custom_ioctl = custom_ioctl,
		.heaps = PLIST_HEAD_INIT(idev->heaps),
		.heap_rwsem = __RWSEM_INITIALIZER(idev->heap_rwsem),
		.dev = {
			.minor = MISC_DYNAMIC_MINOR,
			.name = "ion",
			.fops = &ion_fops
		},
	};

	ret = misc_register(&idev->dev);
	if (ret) {
		kfree(idev);
		return ERR_PTR(ret);
	}

<<<<<<< HEAD
	idev->debug_root = debugfs_create_dir("ion", NULL);
	if (!idev->debug_root) {
		pr_err("ion: failed to create debugfs root directory.\n");
		goto debugfs_done;
	}
	idev->heaps_debug_root = debugfs_create_dir("heaps", idev->debug_root);
	if (!idev->heaps_debug_root) {
		pr_err("ion: failed to create debugfs heaps directory.\n");
		goto debugfs_done;
	}
	idev->clients_debug_root = debugfs_create_dir("clients",
						idev->debug_root);
	if (!idev->clients_debug_root)
		pr_err("ion: failed to create debugfs clients directory.\n");

debugfs_done:

	idev->custom_ioctl = custom_ioctl;
	idev->buffers = RB_ROOT;
	mutex_init(&idev->buffer_lock);
	init_rwsem(&idev->lock);
	plist_head_init(&idev->heaps);
	idev->clients = RB_ROOT;
<<<<<<< HEAD
	ion_root_client = &idev->clients;
	mutex_init(&debugfs_mutex);
	debugfs_create_file("check_all_bufs", 0664, idev->debug_root, idev,
			    &debug_allbufs_fops);
=======
>>>>>>> 2f3a12eca9ce... ion: Rewrite to improve clarity and performance
=======
	ion_dev = idev;
>>>>>>> bd194f1cc4b3... ion: fetch from wahoo
	return idev;
}

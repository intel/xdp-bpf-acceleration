// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 */

/* Devmaps primary use is as a backend map for XDP BPF helper call
 * bpf_redirect_map(). Because XDP is mostly concerned with performance we
 * spent some effort to ensure the datapath with redirect maps does not use
 * any locking. This is a quick note on the details.
 *
 * We have three possible paths to get into the devmap control plane bpf
 * syscalls, bpf programs, and driver side xmit/flush operations. A bpf syscall
 * will invoke an update, delete, or lookup operation. To ensure updates and
 * deletes appear atomic from the datapath side xchg() is used to modify the
 * netdev_map array. Then because the datapath does a lookup into the netdev_map
 * array (read-only) from an RCU critical section we use call_rcu() to wait for
 * an rcu grace period before free'ing the old data structures. This ensures the
 * datapath always has a valid copy. However, the datapath does a "flush"
 * operation that pushes any pending packets in the driver outside the RCU
 * critical section. Each bpf_dtab_netdev tracks these pending operations using
 * a per-cpu flush list. The bpf_dtab_netdev object will not be destroyed  until
 * this list is empty, indicating outstanding flush operations have completed.
 *
 * BPF syscalls may race with BPF program calls on any of the update, delete
 * or lookup operations. As noted above the xchg() operation also keep the
 * netdev_map consistent in this case. From the devmap side BPF programs
 * calling into these operations are the same as multiple user space threads
 * making system calls.
 *
 * Finally, any of the above may race with a netdev_unregister notifier. The
 * unregister notifier must search for net devices in the map structure that
 * contain a reference to the net device and remove them. This is a two step
 * process (a) dereference the bpf_dtab_netdev object in netdev_map and (b)
 * check to see if the ifindex is the same as the net_device being removed.
 * When removing the dev a cmpxchg() is used to ensure the correct dev is
 * removed, in the case of a concurrent update or delete operation it is
 * possible that the initially referenced dev is no longer in the map. As the
 * notifier hook walks the map we know that new dev references can not be
 * added by the user because core infrastructure ensures dev_get_by_index()
 * calls will fail at this point.
 *
 * The devmap_hash type is a map type which interprets keys as ifindexes and
 * indexes these using a hashmap. This allows maps that use ifindex as key to be
 * densely packed instead of having holes in the lookup array for unused
 * ifindexes. The setup and packet enqueue/send code is shared between the two
 * types of devmap; only the lookup and insertion is different.
 */
#include <linux/bpf.h>
#include <net/xdp.h>
#include <linux/filter.h>
#include <trace/events/xdp.h>
#include <linux/btf_ids.h>
#include <linux/pci.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#define DEV_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_ACCELDEVMAP_HASH)

#define ACCELDEV_CTX_BUCKET 8
#define ACCELDEV_CTX_HASHMAX (1 * 1024 * 1024)
#define DEV_MAP_BULK_SIZE_ACCELDEV 16

/* - if enable ACCELDEV_GET_NEXT_KEY_CTX_ENBALED, to acceldev case,
 * map_get_next_key() will get next ctx key(from next acceldev if
 * current acceldev doesn't have one).
 * - if disable ACCELDEV_GET_NEXT_KEY_CTX_ENBALED, map_get_next_key() will
 * get next acceldev.
 */
#define ACCELDEV_GET_NEXT_KEY_CTX_ENBALED 0

/* if enable ACCELDEV_LOOKUP_ELEM_CTX_ENBALED, to acceldev case,
 * dev_map_lookup_elem() will get acceldevmap_val from acceldev_ctx.
 * if disable ACCELDEV_LOOKUP_ELEM_CTX_ENBALED, dev_map_lookup_elem() will
 * get acceldev_handle from acceldev.
 */
#define ACCELDEV_LOOKUP_ELEM_CTX_ENBALED 0

#define ACCELDEV_NUM_MAX (512)
#define ACCELDEV_NUM_MIN (32)

#define GET_KEY_INSTANCE(key) ((u32)(*(u64 *)(key) >> 32))
#define GET_KEY_CTX(key) ((u32)(*(u64 *)(key) & 0x00000000ffffffff))

#define HMASK_TO_BUCKET(n) ((n) + 1)
#define BUCKET_TO_HMASK(n) ((n) - 1)

#define DTAB_STYLE_IS_ACCELDEV(dtab) (is_acceldev(&((dtab)->map)))

struct xdp_dev_bulk_queue {
	struct xdp_frame *q[DEV_MAP_BULK_SIZE];
	struct list_head flush_node;
	struct net_device *dev;
	struct net_device *dev_rx;
	struct bpf_prog *xdp_prog;
	unsigned int count;
};

struct xdp_acceldev_bulk_queue {
	struct xdp_frame *q[DEV_MAP_BULK_SIZE_ACCELDEV];
	struct list_head flush_node;
	struct bpf_dtab_acceldev *acceldev;
	struct net_device *dev_rx;
	struct bpf_prog *xdp_prog;
	unsigned int count;
};


#define CPU_MAP_BULK_SIZE 8  /* 8 == one cacheline on 64-bit archs */
struct xdp_bulk_queue {
	void *q[CPU_MAP_BULK_SIZE];
	struct list_head flush_node;
	struct bpf_dtab_acceldev *obj;
	unsigned int count;
};

struct bpf_dtab_netdev {
	struct net_device *dev; /* must be first member, due to tracepoint */
	struct hlist_node index_hlist;
	struct bpf_dtab *dtab;
	struct bpf_prog *xdp_prog;
	struct rcu_head rcu;
	unsigned int idx;
	struct bpf_devmap_val val;
};

struct bpf_dtab_acceldev;

/* context associated with the acceldevmap_val */
struct bpf_acceldevmap_val_ctx {
	struct hlist_node index_hlist;
	void *ctx;
	int idx;
	struct rcu_head rcu;
	struct bpf_acceldev_ops *acceldev_ops;
	void *acceldev_handle;
	struct bpf_acceldevmap_val acceldevmap_val;
};

/* store the acceldev_ops registered by acceldev driver */
struct bpf_acceldev_ops_data {
	struct list_head list;
	struct rcu_head rcu;
	struct bpf_acceldev_ops acceldev_ops;
};

/* accel dev instance structure */
struct bpf_dtab_acceldev {
	struct pci_dev *dev; /* must be first member, due to tracepoint */
	enum bpf_acceldev_type acceldev_type;
	struct hlist_node index_hlist;
	struct bpf_dtab *dtab;
	struct bpf_prog *xdp_prog;
	struct net_device *dev_rx;
	struct rcu_head rcu;

	/* acceldev instance, created only once when it's first selected by user
	 * with acceldevmap_val, may be shared with other ctx/acceldevmap_val
	 */
	void *acceldev_handle;
	int idx; /* map key */

	/* from acceldev_ops_list with the same pci_dev */
	struct bpf_acceldev_ops *acceldev_ops;

	/* ctx list associated with the acceldev_handle */
	struct hlist_head *ctx_idx_head;
	/* refers to __xfrm_state_lookup() */
	unsigned int		ctx_items;
	unsigned int		ctx_n_buckets;
	struct work_struct	ctx_hash_work;
	seqcount_spinlock_t ctx_seqcount_lock;
	spinlock_t			ctx_lock; /* Used for ctx operation in acceldev */

	struct xdp_acceldev_bulk_queue __percpu *bq;

	/* For acceldev enqueue and IRQ processing on the specified cpu */
	u32 cpu;    /* kthread CPU and map index */
	/* int map_id; */ /* Back reference to map */

	struct xdp_bulk_queue __percpu *bulkq;

	/* the queue associated with current acceldev instance.
	 * one instance correpsonding to only one queue
	 */
	struct ptr_ring *queue;

	/* single-consumer kthread */
	struct task_struct *kthread;
	atomic_t refcnt; /* Control when this struct can be free'ed */
	struct work_struct kthread_stop_wq;
};

struct bpf_dtab {
	struct bpf_map map;
	struct bpf_dtab_netdev __rcu **netdev_map; /* DEVMAP type only */
	struct list_head list;

	/* these are only used for DEVMAP_HASH type maps */
	enum bpf_dev_type dev_type;
	struct hlist_head *dev_index_head;
	spinlock_t index_lock; /* Used for acceldev operation in dtab */
	unsigned int items;
	u32 n_buckets;
};

static DEFINE_PER_CPU(struct list_head, dev_flush_list);
static DEFINE_PER_CPU(struct list_head, acceldev_flush_list);
static DEFINE_PER_CPU(struct list_head, acceldev_flush_list_on_rcpu);


static DEFINE_SPINLOCK(dev_map_lock);
static LIST_HEAD(dev_map_list);
static DEFINE_SPINLOCK(acceldev_ops_data_lock);
static LIST_HEAD(acceldev_ops_data_list); /* bpf_acceldevmap_register() */
static bool batch_enabled = true;

static void bq_flush_to_queue(struct xdp_bulk_queue *bq)
{
	struct bpf_dtab_acceldev *rcpu = bq->obj;
	unsigned int processed = 0, drops = 0;
	struct ptr_ring *q;
	int i;

	if (unlikely(!bq->count))
		return;

	q = rcpu->queue;
	spin_lock(&q->producer_lock);

	for (i = 0; i < bq->count; i++) {
		struct xdp_frame *xdpf = bq->q[i];
		int err;

		err = __ptr_ring_produce(q, xdpf);
		if (err) {
			drops++;
			xdp_return_frame_rx_napi(xdpf);
		}
		processed++;
	}
	bq->count = 0;
	spin_unlock(&q->producer_lock);

	__list_del_clearprev(&bq->flush_node);
}

/* Runs under RCU-read-side, plus in softirq under NAPI protection.
 * Thus, safe percpu variable access.
 */
static int acceldev_bulkq_enqueue(struct bpf_dtab_acceldev *rcpu, struct xdp_frame *xdpf)
{
	struct list_head *flush_list = this_cpu_ptr(&acceldev_flush_list_on_rcpu);
	struct xdp_bulk_queue *bq = this_cpu_ptr(rcpu->bulkq);

	if (unlikely(bq->count == CPU_MAP_BULK_SIZE))
		bq_flush_to_queue(bq);

	/* Notice, xdp_buff/page MUST be queued here, long enough for
	 * driver to code invoking us to finished, due to driver
	 * (e.g. ixgbe) recycle tricks based on page-refcnt.
	 *
	 * Thus, incoming xdp_frame is always queued here (else we race
	 * with another CPU on page-refcnt and remaining driver code).
	 * Queue time is very short, as driver will invoke flush
	 * operation, when completing napi->poll call.
	 */
	bq->q[bq->count++] = xdpf;

	if (!bq->flush_node.prev)
		list_add(&bq->flush_node, flush_list);

	return 0;
}


bool is_acceldev(struct bpf_map *map)
{
	struct bpf_dtab *dtab;

	if (likely(map) && map->map_type == BPF_MAP_TYPE_DEVMAP_HASH) {
		dtab = container_of(map, struct bpf_dtab, map);
		if (dtab->dev_type == BPF_ACCEL_DEV)
			return true;
	}
	return false;
}

static struct hlist_head *dev_map_create_hash(unsigned int entries,
					      int numa_node)
{
	int i;
	struct hlist_head *hash;

	hash = bpf_map_area_alloc((u64)entries * sizeof(*hash), numa_node);
	if (!hash)
		for (i = 0; i < entries; i++)
			INIT_HLIST_HEAD(&hash[i]);

	return hash;
}

static inline struct hlist_head *dev_map_index_hash(struct bpf_dtab *dtab,
						    int idx)
{
	return &dtab->dev_index_head[idx & (dtab->n_buckets - 1)];
}

static inline unsigned int acceldev_ctx_map_index_hash_with_mask(int idx, unsigned int hashmask)
{
	unsigned int h = (__force u32)idx;

	h = (h ^ (h >> 10) ^ (h >> 20)) & hashmask;
	return h;
}

static inline struct hlist_head *acceldev_ctx_map_index_hash(struct bpf_dtab_acceldev *acceldev,
							     int idx)
{
	int hmask = BUCKET_TO_HMASK(acceldev->ctx_n_buckets);
	int sz = acceldev_ctx_map_index_hash_with_mask(idx, hmask);

	return acceldev->ctx_idx_head + sz;
}

static void __acceldev_entry_free_no_destory(struct rcu_head *rcu)
{
	struct bpf_dtab_acceldev *acceldev;

	acceldev = container_of(rcu, struct bpf_dtab_acceldev, rcu);
	kfree(acceldev);
}

void bpf_acceldevmap_set_single_mode(bool status)
{
	if (status)
		batch_enabled = false;
	else
		batch_enabled = true;
}
EXPORT_SYMBOL(bpf_acceldevmap_set_single_mode);

static int weight = 64;
static int cr_enabled = 0;
void bpf_acceldevmap_cfg_kthread(int _weight, int _cr_enabled)
{
	weight = _weight;
	cr_enabled = _cr_enabled;
	printk("weight is %u, cr_enabled is %u\n",
			weight, cr_enabled);
}
EXPORT_SYMBOL(bpf_acceldevmap_cfg_kthread);

static int acceldev_map_kthread_run(void *data)
{
	struct bpf_dtab_acceldev *rcpu = data;
	struct xdp_acceldev_bulk_queue *acceldev_bq = this_cpu_ptr(rcpu->bq);

	set_current_state(TASK_INTERRUPTIBLE);

	/* When kthread gives stop order, then rcpu have been disconnected
	 * from map, thus no new packets can enter. Remaining in-flight
	 * per CPU stored packets are flushed to this queue.  Wait honoring
	 * kthread_stop signal until queue is empty.
	 */
	while (!kthread_should_stop() || !__ptr_ring_empty(rcpu->queue)) {
		unsigned int sched = 0;
		int i, n;
		void *frames[DEV_MAP_BULK_SIZE_ACCELDEV];
		int frame_count = 0;

		/* Release CPU reschedule checks */
		if (__ptr_ring_empty(rcpu->queue)) {
			set_current_state(TASK_INTERRUPTIBLE);
			/* Recheck to avoid lost wake-up */
			if (__ptr_ring_empty(rcpu->queue)) {
				schedule();
				sched = 1;
			} else {
				__set_current_state(TASK_RUNNING);
			}
		} else {
			if(cr_enabled)
				sched = cond_resched();
		}

		/*
		 * single consumer, with this
		 * kthread CPU pinned. Lockless access to ptr_ring
		 * consume side valid as no-resize allowed of queue.
		 */

		do {
		n = __ptr_ring_consume_batched(rcpu->queue, frames,
					       DEV_MAP_BULK_SIZE_ACCELDEV);
		for (i = 0; i < n; i++) {
			struct page *page;
			struct xdp_frame *xdpf = frames[i];

			page = virt_to_page(xdpf);

			/* Bring struct page memory area to curr CPU */
			prefetchw(page);
			acceldev_bq->q[i] = xdpf;
			acceldev_bq->count++;
			frame_count++;
		}

		if (acceldev_bq->count > 0) {
#if 0
			local_bh_disable();
#endif
			rcpu->acceldev_ops->enqueue(rcpu->acceldev_handle,
						    rcpu,
						    acceldev_bq->q,
						    acceldev_bq->count,
						    rcpu->xdp_prog,
						    rcpu->dev_rx);
#if 0
			local_bh_enable(); /* resched point, may call do_softirq() */
#endif
			acceldev_bq->count = 0;
		}
		} while ((frame_count < weight) && (n != 0));
	}
	__set_current_state(TASK_RUNNING);

	return 0;
}

/* exported to acceldev driver */
int bpf_acceldevmap_register(struct bpf_acceldev_ops *acceldev_ops)
{
	/* Add acceldev_ops into acceldev_ops_list */
	struct bpf_acceldev_ops_data *ops_new;
	struct bpf_acceldev_ops_data *ops_old;
	struct bpf_dtab *dtab;
	int i;
	unsigned long flags;
	int cpu;

	if (!acceldev_ops ||
	    acceldev_ops->acceldev_type >= BPF_ACCELDEV_MAX ||
		!acceldev_ops->create_instance ||
		!acceldev_ops->destroy_instance ||
		!acceldev_ops->create_ctx ||
		!acceldev_ops->destroy_ctx ||
		!acceldev_ops->enqueue) {
		return -EINVAL;
	}

	/*
	 * trace_printk("bpf_acceldevmap_register called. accledev_name:%s, acceldev_type:%d\n",
	 *    acceldev_ops->acceldev_name, acceldev_ops->acceldev_type);
	 */

	/* Add acceldev_ops to acceldev_ops_data_list*/
	spin_lock(&acceldev_ops_data_lock);
	list_for_each_entry(ops_old, &acceldev_ops_data_list, list) {
		if (acceldev_ops->acceldev_type == ops_old->acceldev_ops.acceldev_type &&
		    acceldev_ops->dev == ops_old->acceldev_ops.dev) {
			/* Reject duplicate register */
			spin_unlock(&acceldev_ops_data_lock);
			kfree(ops_new);
			return -EINVAL;
		}
	}

	ops_new = bpf_map_area_alloc(sizeof(*ops_new), NUMA_NO_NODE);
	if (!ops_new)
		return -ENOMEM;

	memcpy(ops_new->acceldev_ops.acceldev_name, acceldev_ops->acceldev_name, MAX_ACCEL_NAME);
	ops_new->acceldev_ops.acceldev_type = acceldev_ops->acceldev_type;
	ops_new->acceldev_ops.dev = acceldev_ops->dev;
	ops_new->acceldev_ops.create_instance = acceldev_ops->create_instance;
	ops_new->acceldev_ops.destroy_instance = acceldev_ops->destroy_instance;
	ops_new->acceldev_ops.create_ctx = acceldev_ops->create_ctx;
	ops_new->acceldev_ops.destroy_ctx = acceldev_ops->destroy_ctx;
	ops_new->acceldev_ops.enqueue = acceldev_ops->enqueue;

	list_add_tail(&ops_new->list, &acceldev_ops_data_list);
	spin_unlock(&acceldev_ops_data_lock);

	/* Add acceldev_ops to acceldev hlist */
	rcu_read_lock();
	list_for_each_entry_rcu(dtab, &dev_map_list, list) {
		if (DTAB_STYLE_IS_ACCELDEV(dtab) ||
		    dtab->map.map_type != BPF_MAP_TYPE_DEVMAP_HASH) {
			continue;
		}

		spin_lock_irqsave(&dtab->index_lock, flags);
		for (i = 0; i < dtab->n_buckets; i++) {
			struct bpf_dtab_acceldev *odev;
			struct bpf_dtab_acceldev *ndev;
			struct hlist_head *head;

			head = dev_map_index_hash(dtab, i);
			hlist_for_each_entry_rcu(odev, head, index_hlist) {
				if (odev->acceldev_type == ops_new->acceldev_ops.acceldev_type &&
				    odev->dev == ops_new->acceldev_ops.dev &&
					!odev->acceldev_ops) {
					/* Don't call __acceldev_map_alloc_node(),
					 * because no need to init again.
					 */
					ndev = bpf_map_kmalloc_node(&dtab->map, sizeof(*ndev),
								    GFP_NOWAIT | __GFP_NOWARN,
									dtab->map.numa_node);
					if (!ndev)
						return -ENOMEM;
				}

				memcpy(ndev, odev, sizeof(*ndev));
				for_each_possible_cpu(cpu) {
					per_cpu_ptr(ndev->bq, cpu)->acceldev = ndev;
				}

				ndev->acceldev_ops = &ops_new->acceldev_ops;
				hlist_del_rcu(&odev->index_hlist);
				hlist_add_head_rcu(&ndev->index_hlist,
						   dev_map_index_hash(dtab, ndev->idx));
				call_rcu(&odev->rcu, __acceldev_entry_free_no_destory);
			}
		}
		spin_unlock_irqrestore(&dtab->index_lock, flags);
	}
	rcu_read_unlock();

	return 0;
}
EXPORT_SYMBOL(bpf_acceldevmap_register);

/* exported to acceldev driver */
int bpf_acceldevmap_unregister(struct bpf_acceldev_ops *acceldev_ops)
{
	struct bpf_acceldev_ops_data *ops_old;
	struct bpf_dtab *dtab;
	int i;
	unsigned long flags;
	int cpu;

	/* Remove acceldev_ops from acceldev hlist */
	rcu_read_lock();
	list_for_each_entry_rcu(dtab, &dev_map_list, list) {
		if (!DTAB_STYLE_IS_ACCELDEV(dtab) ||
		    dtab->map.map_type != BPF_MAP_TYPE_DEVMAP_HASH)
			continue;

		spin_lock_irqsave(&dtab->index_lock, flags);
		for (i = 0; i < dtab->n_buckets; i++) {
			struct bpf_dtab_acceldev *odev;
			struct bpf_dtab_acceldev *ndev;
			struct hlist_head *head;
			struct hlist_node *next;

			head = dev_map_index_hash(dtab, i);

			hlist_for_each_entry_safe(odev, next, head, index_hlist) {
				if (odev->dev == acceldev_ops->dev &&
				    odev->acceldev_ops)	{
					/* Don't call __acceldev_map_alloc_node(),
					 * because no need to init again.
					 */
					ndev = bpf_map_kmalloc_node(&dtab->map, sizeof(*ndev),
								    GFP_NOWAIT | __GFP_NOWARN,
									dtab->map.numa_node);
					if (!ndev)
						return -ENOMEM;

					memcpy(ndev, odev, sizeof(*ndev));
					for_each_possible_cpu(cpu) {
						per_cpu_ptr(ndev->bq, cpu)->acceldev = ndev;
					}

					ndev->acceldev_ops = NULL;
					hlist_del_rcu(&odev->index_hlist);
					hlist_add_head_rcu(&ndev->index_hlist,
							   dev_map_index_hash(dtab, ndev->idx));
					call_rcu(&odev->rcu, __acceldev_entry_free_no_destory);
				}
			}
		}
		spin_unlock_irqrestore(&dtab->index_lock, flags);
	}
	rcu_read_unlock();

	synchronize_rcu();

	/* Remove acceldev_ops from acceldev_ops_list */
	spin_lock(&acceldev_ops_data_lock);
	list_for_each_entry(ops_old, &acceldev_ops_data_list, list) {
		if (acceldev_ops->acceldev_type == ops_old->acceldev_ops.acceldev_type &&
		    acceldev_ops->dev == ops_old->acceldev_ops.dev) {
			list_del(&ops_old->list);
			kfree(ops_old);
			break;
		}
	}
	spin_unlock(&acceldev_ops_data_lock);

	return 0;
}
EXPORT_SYMBOL(bpf_acceldevmap_unregister);

static int dev_map_init_map(struct bpf_dtab *dtab, union bpf_attr *attr)
{
	u32 valsize = attr->value_size;

	/* check sanity of attributes. 2 value sizes supported:
	 * 4 bytes: ifindex
	 * 8 bytes: ifindex + prog fd
	 */
	if (attr->max_entries == 0 || (attr->key_size != 4 && attr->key_size != 8) ||
	    (valsize != offsetofend(struct bpf_devmap_val, ifindex) &&
		valsize != offsetofend(struct bpf_devmap_val, bpf_prog.fd) &&
		attr->key_size != 8) ||
		attr->map_flags & ~DEV_CREATE_FLAG_MASK)
		return -EINVAL;

	/* Lookup returns a pointer straight to dev->ifindex, so make sure the
	 * verifier prevents writes from the BPF side
	 */
	attr->map_flags |= BPF_F_RDONLY_PROG;

	/* Set dev_type */
	if (attr->map_flags & BPF_F_ACCELDEVMAP_HASH)
		dtab->dev_type = BPF_ACCEL_DEV;
	else
		dtab->dev_type = BPF_NET_DEV;

	bpf_map_init_from_attr(&dtab->map, attr);

	/* Set MIN & MAX entry size of acceldev */
	if (dtab->dev_type == BPF_ACCEL_DEV) {
		if (dtab->map.max_entries < ACCELDEV_NUM_MIN) {
			/* trace_printk("max_entries :%d too small, set to min value : %d\n",
			 * dtab->map.max_entries, ACCELDEV_NUM_MIN);
			 */
			dtab->map.max_entries = ACCELDEV_NUM_MIN;
		}
		if (dtab->map.max_entries > ACCELDEV_NUM_MAX) {
			/* trace_printk("max_entries :%d too big, set to max value : %d\n",
			 * dtab->map.max_entries, ACCELDEV_NUM_MAX);
			 */
			dtab->map.max_entries = ACCELDEV_NUM_MAX;
		}
	}

	if (attr->map_type == BPF_MAP_TYPE_DEVMAP_HASH) {
		dtab->n_buckets = roundup_pow_of_two(dtab->map.max_entries);

		if (!dtab->n_buckets) /* Overflow check */
			return -EINVAL;
	}

	if (attr->map_type == BPF_MAP_TYPE_DEVMAP_HASH) {
		dtab->dev_index_head = dev_map_create_hash(dtab->n_buckets,
							   dtab->map.numa_node);
		if (!dtab->dev_index_head)
			return -ENOMEM;

		spin_lock_init(&dtab->index_lock);
	} else {
		dtab->netdev_map = bpf_map_area_alloc((u64) dtab->map.max_entries *
						      sizeof(struct bpf_dtab_netdev *),
						      dtab->map.numa_node);
		if (!dtab->netdev_map)
			return -ENOMEM;
	}

	return 0;
}

static struct bpf_map *dev_map_alloc(union bpf_attr *attr)
{
	struct bpf_dtab *dtab;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);

	dtab = bpf_map_area_alloc(sizeof(*dtab), NUMA_NO_NODE);
	if (!dtab)
		return ERR_PTR(-ENOMEM);

	err = dev_map_init_map(dtab, attr);
	if (err) {
		bpf_map_area_free(dtab);
		return ERR_PTR(err);
	}

	spin_lock(&dev_map_lock);
	list_add_tail_rcu(&dtab->list, &dev_map_list);
	spin_unlock(&dev_map_lock);

	return &dtab->map;
}

void acceldev_ctx_hash_free(struct hlist_head *n, unsigned int sz)
{
	if (sz <= PAGE_SIZE)
		kfree(n);
	else if (hashdist)
		vfree(n);
	else
		free_pages((unsigned long)n, get_order(sz));
}

void acceldev_destroy_instance(struct bpf_dtab_acceldev *acceldev)
{
	if (acceldev->acceldev_ops &&
	    acceldev->acceldev_ops->destroy_instance)
		acceldev->acceldev_ops->destroy_instance(acceldev->acceldev_handle);
}

void acceldev_destroy_ctx(struct bpf_dtab_acceldev *acceldev, struct bpf_acceldevmap_val_ctx *ctx)
{
	if (acceldev->acceldev_ops &&
	    acceldev->acceldev_ops->destroy_ctx)
		acceldev->acceldev_ops->destroy_ctx(acceldev->acceldev_handle, ctx->ctx);
}

static void dev_map_free(struct bpf_map *map)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	int i, j;

	/* At this point bpf_prog->aux->refcnt == 0 and this map->refcnt == 0,
	 * so the programs (can be more than one that used this map) were
	 * disconnected from events. The following synchronize_rcu() guarantees
	 * both rcu read critical sections complete and waits for
	 * preempt-disable regions (NAPI being the relevant context here) so we
	 * are certain there will be no further reads against the netdev_map and
	 * all flush operations are complete. Flush operations can only be done
	 * from NAPI context for this reason.
	 */

	spin_lock(&dev_map_lock);
	list_del_rcu(&dtab->list);
	spin_unlock(&dev_map_lock);

	bpf_clear_redirect_map(map);
	synchronize_rcu();

	/* Make sure prior __dev_map_entry_free() have completed. */
	rcu_barrier();

	if (dtab->map.map_type == BPF_MAP_TYPE_DEVMAP_HASH && DTAB_STYLE_IS_ACCELDEV(dtab)) {
		for (i = 0; i < dtab->n_buckets; i++) {
			struct bpf_dtab_acceldev *acceldev;
			struct hlist_head *head, *chead;
			struct hlist_node *next;

			head = dev_map_index_hash(dtab, i);

			hlist_for_each_entry_safe(acceldev, next, head, index_hlist) {
				/* acceldev:Double Hash remove START */
				unsigned int hmask = BUCKET_TO_HMASK(acceldev->ctx_n_buckets);
				unsigned int sz = (hmask + 1) * sizeof(struct hlist_head);

				for (j = 0; j <= hmask; j++) {
					struct bpf_acceldevmap_val_ctx *ctx;
					struct hlist_node *nctx;

					chead = acceldev->ctx_idx_head + j;
					hlist_for_each_entry_safe(ctx, nctx, chead, index_hlist) {
						hlist_del_rcu(&ctx->index_hlist);
						acceldev_destroy_ctx(acceldev, ctx);
						acceldev->ctx_items--;
						kfree(ctx);
					}
				}
				WARN_ON(!hlist_empty(acceldev->ctx_idx_head));
				acceldev_ctx_hash_free(acceldev->ctx_idx_head, sz);
				/* acceldev:Double Hash remove END */

				hlist_del_rcu(&acceldev->index_hlist);
				acceldev_destroy_instance(acceldev);
				if (acceldev->xdp_prog)
					bpf_prog_put(acceldev->xdp_prog);
				pci_dev_put(acceldev->dev);
				kfree(acceldev);
			}
		}
	} else if (dtab->map.map_type == BPF_MAP_TYPE_DEVMAP_HASH) {
		for (i = 0; i < dtab->n_buckets; i++) {
			struct bpf_dtab_netdev *dev;
			struct hlist_head *head;
			struct hlist_node *next;

			head = dev_map_index_hash(dtab, i);

			hlist_for_each_entry_safe(dev, next, head, index_hlist) {
				hlist_del_rcu(&dev->index_hlist);
				if (dev->xdp_prog)
					bpf_prog_put(dev->xdp_prog);
				dev_put(dev->dev);
				kfree(dev);
			}
		}
		bpf_map_area_free(dtab->dev_index_head);
	} else {
		for (i = 0; i < dtab->map.max_entries; i++) {
			struct bpf_dtab_netdev *dev;

			dev = rcu_dereference_raw(dtab->netdev_map[i]);
			if (!dev)
				continue;

			if (dev->xdp_prog)
				bpf_prog_put(dev->xdp_prog);
			dev_put(dev->dev);
			kfree(dev);
		}

		bpf_map_area_free(dtab->netdev_map);
	}

	bpf_map_area_free(dtab);
}

static int dev_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = next_key;

	if (index >= dtab->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == dtab->map.max_entries - 1)
		return -ENOENT;
	*next = index + 1;
	return 0;
}

/* Elements are kept alive by RCU; either by rcu_read_lock() (from syscall) or
 * by local_bh_disable() (from XDP calls inside NAPI). The
 * rcu_read_lock_bh_held() below makes lockdep accept both.
 */
static void *__dev_map_hash_lookup_elem(struct bpf_map *map, u32 key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct hlist_head *head = dev_map_index_hash(dtab, key);
	struct bpf_dtab_netdev *dev;

	hlist_for_each_entry_rcu(dev, head, index_hlist,
				 lockdep_is_held(&dtab->index_lock))
		if (dev->idx == key)
			return dev;

	return NULL;
}

static void *__acceldev_map_hash_lookup_elem(struct bpf_map *map, u32 key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct hlist_head *head = dev_map_index_hash(dtab, key);
	struct bpf_dtab_acceldev *acceldev;

	hlist_for_each_entry_rcu(acceldev, head, index_hlist,
				 lockdep_is_held(&dtab->index_lock)) {
		if (acceldev->idx == key)
			return acceldev;
	}
	return NULL;
}

static void *__acceldev_ctx_map_hash_lookup_elem(struct bpf_dtab_acceldev *acceldev, u32 key)
{
	struct bpf_acceldevmap_val_ctx *acceldev_ctx;
	struct hlist_head *acceldev_ctx_head;

	acceldev_ctx_head = acceldev_ctx_map_index_hash(acceldev, key);
	hlist_for_each_entry_rcu(acceldev_ctx, acceldev_ctx_head, index_hlist) {
		if (acceldev_ctx->idx == key)
			return acceldev_ctx;
	}

	return NULL;
}

static int dev_map_hash_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	u32 idx, *next = next_key;
	struct bpf_dtab_netdev *dev, *next_dev;
	struct hlist_head *head;
	int i = 0;

	/* For acceldev */
	u64 *acceldev_next = next_key;
	struct bpf_dtab_acceldev *adev, *nadev;
	u32 key_instance;
#if ACCELDEV_GET_NEXT_KEY_CTX_ENBALED
	struct bpf_acceldevmap_val_ctx *ctx, *nctx;
#endif

	if (!key)
		goto find_first;

	if (dtab->dev_type == BPF_NET_DEV) {
		idx = *(u32 *)key;

		dev = __dev_map_hash_lookup_elem(map, idx);
		if (!dev)
			goto find_first;

		next_dev = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&dev->index_hlist)),
					    struct bpf_dtab_netdev, index_hlist);

		if (next_dev) {
			*next = next_dev->idx;
			return 0;
		}

		i = idx & (dtab->n_buckets - 1);
		i++;
	} else if (!DTAB_STYLE_IS_ACCELDEV(dtab)) {
		return -ENOENT;
	}
#if ACCELDEV_GET_NEXT_KEY_CTX_ENBALED
	u32 key_ctx;

	key_instance = GET_KEY_INSTANCE(key);
	key_ctx = GET_KEY_CTX(key);

	adev = __acceldev_map_hash_lookup_elem(map, key_instance);
	if (!adev)
		goto find_first;

	/* From ctx hash list - Start */
	ctx = __acceldev_ctx_map_hash_lookup_elem(adev, key_ctx);
	if (!ctx)
		goto find_first;

	nctx = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&ctx->index_hlist)),
				struct bpf_acceldevmap_val_ctx, index_hlist);

	if (nctx) {
		*acceldev_next = (u64)nctx->idx;
		*acceldev_next &= ((u64)adev->idx) << 32;
		return 0;
	}
	/* From ctx hash list - End */

	nadev = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&adev->index_hlist)),
				 struct bpf_dtab_acceldev, index_hlist);

	if (nadev) {
		nctx = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(nadev->ctx_idx_head)),
					struct bpf_acceldevmap_val_ctx, index_hlist);

		if (nctx) {
			*acceldev_next = (u64)nctx->idx;
			*acceldev_next &= ((u64)nadev->idx) << 32;
			return 0;
		}
	}

	i = idx & (dtab->n_buckets - 1);
	i++;
#else
	key_instance = GET_KEY_INSTANCE(key);

	adev = __acceldev_map_hash_lookup_elem(map, key_instance);
	if (!adev)
		goto find_first;

	nadev = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&adev->index_hlist)),
				 struct bpf_dtab_acceldev, index_hlist);

	if (nadev) {
		*acceldev_next = nadev->idx;
		return 0;
	}

	i = idx & (dtab->n_buckets - 1);
	i++;
#endif

find_first:
	if (dtab->dev_type == BPF_NET_DEV) {
		for (; i < dtab->n_buckets; i++) {
			head = dev_map_index_hash(dtab, i);

			next_dev = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),
						    struct bpf_dtab_netdev,
						    index_hlist);
			if (next_dev) {
				*next = next_dev->idx;
				return 0;
			}
		}
	} else if (DTAB_STYLE_IS_ACCELDEV(dtab)) {
#if ACCELDEV_GET_NEXT_KEY_CTX_ENBALED
		for (; i < dtab->n_buckets; i++) {
			head = dev_map_index_hash(dtab, i);

			nadev = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),
						 struct bpf_dtab_acceldev,
						    index_hlist);

			if (nadev) {
				head = nadev->ctx_idx_head;
				nctx = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),
							struct bpf_acceldevmap_val_ctx,
							index_hlist);

				if (nctx) {
					*acceldev_next = (u64)nctx->idx;
					*acceldev_next &= ((u64)nadev->idx) << 32;
					return 0;
				}
			}
		}
#else
		for (; i < dtab->n_buckets; i++) {
			head = dev_map_index_hash(dtab, i);

			nadev = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),
						 struct bpf_dtab_acceldev,
							index_hlist);
			if (nadev) {
				*acceldev_next = nadev->idx;
				return 0;
			}
		}
#endif
	}

	return -ENOENT;
}

static int dev_map_bpf_prog_run(struct bpf_prog *xdp_prog,
				struct xdp_frame **frames, int n,
				struct net_device *dev)
{
	struct xdp_txq_info txq = { .dev = dev };
	struct xdp_buff xdp;
	int i, nframes = 0;

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];
		u32 act;
		int err;

		xdp_convert_frame_to_buff(xdpf, &xdp);
		xdp.txq = &txq;

		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		switch (act) {
		case XDP_PASS:
			err = xdp_update_frame_from_buff(&xdp, xdpf);
			if (unlikely(err < 0))
				xdp_return_frame_rx_napi(xdpf);
			else
				frames[nframes++] = xdpf;
			break;
		default:
			bpf_warn_invalid_xdp_action(NULL, xdp_prog, act);
			fallthrough;
		case XDP_ABORTED:
			trace_xdp_exception(dev, xdp_prog, act);
			fallthrough;
		case XDP_DROP:
			xdp_return_frame_rx_napi(xdpf);
			break;
		}
	}
	return nframes; /* sent frames count */
}

static void acceldev_bq_xmit_all(struct xdp_acceldev_bulk_queue *acceldev_bq, u32 flags)
{
	struct bpf_dtab_acceldev *acceldev = acceldev_bq->acceldev;
	unsigned int cnt = acceldev_bq->count;
	u32 to_send = cnt;
	int i;
	struct xdp_frame *xdpf;

	if (unlikely(!cnt))
		return;

	for (i = 0; i < cnt; i++) {
		xdpf = acceldev_bq->q[i];
		prefetch(xdpf);
	}

	acceldev->acceldev_ops->enqueue(acceldev_bq->acceldev->acceldev_handle,
								   acceldev_bq->acceldev,
								   acceldev_bq->q,
								   to_send,
								   acceldev_bq->xdp_prog,
								   acceldev_bq->dev_rx);

	/* Failure process will add here in the future */

	acceldev_bq->count = 0;
}

static void bq_xmit_all(struct xdp_dev_bulk_queue *bq, u32 flags)
{
	struct net_device *dev = bq->dev;
	unsigned int cnt = bq->count;
	int sent = 0, err = 0;
	int to_send = cnt;
	int i;

	if (unlikely(!cnt))
		return;

	for (i = 0; i < cnt; i++) {
		struct xdp_frame *xdpf = bq->q[i];

		prefetch(xdpf);
	}

	if (bq->xdp_prog) {
		to_send = dev_map_bpf_prog_run(bq->xdp_prog, bq->q, cnt, dev);
		if (!to_send)
			goto out;
	}

	sent = dev->netdev_ops->ndo_xdp_xmit(dev, to_send, bq->q, flags);
	if (sent < 0) {
		/* If ndo_xdp_xmit fails with an errno, no frames have
		 * been xmit'ed.
		 */
		err = sent;
		sent = 0;
	}

	/* If not all frames have been transmitted, it is our
	 * responsibility to free them
	 */
	for (i = sent; unlikely(i < to_send); i++)
		xdp_return_frame_rx_napi(bq->q[i]);

out:
	bq->count = 0;
	trace_xdp_devmap_xmit(bq->dev_rx, dev, sent, cnt - sent, err);
}

/* __dev_flush is called from xdp_do_flush() which _must_ be signalled from the
 * driver before returning from its napi->poll() routine. See the comment above
 * xdp_do_flush() in filter.c.
 */
void __dev_flush(void)
{
	struct list_head *flush_list = this_cpu_ptr(&dev_flush_list);
	struct xdp_dev_bulk_queue *bq, *tmp;
	struct xdp_acceldev_bulk_queue *acceldev_bq, *acceldev_tmp;
	struct xdp_bulk_queue *bulkq, *acceldev_on_rcpu_tmp;

	list_for_each_entry_safe(bq, tmp, flush_list, flush_node) {
		bq_xmit_all(bq, XDP_XMIT_FLUSH);
		bq->dev_rx = NULL;
		bq->xdp_prog = NULL;
		__list_del_clearprev(&bq->flush_node);
	}

	flush_list = this_cpu_ptr(&acceldev_flush_list);
	list_for_each_entry_safe(acceldev_bq, acceldev_tmp, flush_list, flush_node) {
		acceldev_bq_xmit_all(acceldev_bq, XDP_XMIT_FLUSH);
		acceldev_bq->dev_rx = NULL;
		acceldev_bq->xdp_prog = NULL;
		__list_del_clearprev(&acceldev_bq->flush_node);
	}


	flush_list = this_cpu_ptr(&acceldev_flush_list_on_rcpu);
	list_for_each_entry_safe(bulkq, acceldev_on_rcpu_tmp, flush_list, flush_node) {
		bq_flush_to_queue(bulkq);
		/* If already running, costs spin_lock_irqsave + smb_mb */
		wake_up_process(bulkq->obj->kthread);
	}

}

/* Elements are kept alive by RCU; either by rcu_read_lock() (from syscall) or
 * by local_bh_disable() (from XDP calls inside NAPI). The
 * rcu_read_lock_bh_held() below makes lockdep accept both.
 */
static void *__dev_map_lookup_elem(struct bpf_map *map, u32 key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *obj;

	if (key >= map->max_entries)
		return NULL;

	obj = rcu_dereference_check(dtab->netdev_map[key],
				    rcu_read_lock_bh_held());
	return obj;
}

/* Runs in NAPI, i.e., softirq under local_bh_disable(). Thus, safe percpu
 * variable access, and map elements stick around. See comment above
 * xdp_do_flush() in filter.c.
 */
static void bq_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
		       struct net_device *dev_rx, struct bpf_prog *xdp_prog)
{
	struct list_head *flush_list = this_cpu_ptr(&dev_flush_list);
	struct xdp_dev_bulk_queue *bq = this_cpu_ptr(dev->xdp_bulkq);

	if (unlikely(bq->count == DEV_MAP_BULK_SIZE))
		bq_xmit_all(bq, 0);

	/* Ingress dev_rx will be the same for all xdp_frame's in
	 * bulk_queue, because bq stored per-CPU and must be flushed
	 * from net_device drivers NAPI func end.
	 *
	 * Do the same with xdp_prog and flush_list since these fields
	 * are only ever modified together.
	 */
	if (!bq->dev_rx) {
		bq->dev_rx = dev_rx;
		bq->xdp_prog = xdp_prog;
		list_add(&bq->flush_node, flush_list);
	}

	bq->q[bq->count++] = xdpf;
}

static void acceldev_bq_enqueue(struct bpf_dtab_acceldev *acceldev, struct xdp_frame *xdpf,
				struct net_device *dev_rx, struct bpf_prog *xdp_prog)
{
	struct list_head *flush_list = this_cpu_ptr(&acceldev_flush_list);
	struct xdp_acceldev_bulk_queue *acceldev_bq;

	acceldev_bq = this_cpu_ptr(acceldev->bq);
	if (unlikely(acceldev_bq->count == DEV_MAP_BULK_SIZE_ACCELDEV))
		acceldev_bq_xmit_all(acceldev_bq, 0);

	if (!acceldev_bq->dev_rx) {
		acceldev_bq->dev_rx = dev_rx;
		acceldev_bq->xdp_prog = xdp_prog;
		list_add(&acceldev_bq->flush_node, flush_list);
	}

	acceldev_bq->q[acceldev_bq->count++] = xdpf;
}

static inline int __xdp_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
				struct net_device *dev_rx,
				struct bpf_prog *xdp_prog)
{
	int err;

	if (!dev->netdev_ops->ndo_xdp_xmit)
		return -EOPNOTSUPP;

	err = xdp_ok_fwd_dev(dev, xdp_get_frame_len(xdpf));
	if (unlikely(err))
		return err;

	bq_enqueue(dev, xdpf, dev_rx, xdp_prog);
	return 0;
}

static inline int __acceldev_enqueue(struct bpf_dtab_acceldev *acceldev, struct xdp_frame *xdpf,
				     struct net_device *dev_rx,
					struct bpf_prog *xdp_prog)
{
	acceldev_bq_enqueue(acceldev, xdpf, dev_rx, xdp_prog);
	return 0;
}

static u32 dev_map_bpf_prog_run_skb(struct sk_buff *skb, struct bpf_dtab_netdev *dst)
{
	struct xdp_txq_info txq = { .dev = dst->dev };
	struct xdp_buff xdp;
	u32 act;

	if (!dst->xdp_prog)
		return XDP_PASS;

	__skb_pull(skb, skb->mac_len);
	xdp.txq = &txq;

	act = bpf_prog_run_generic_xdp(skb, &xdp, dst->xdp_prog);
	switch (act) {
	case XDP_PASS:
		__skb_push(skb, skb->mac_len);
		break;
	default:
		bpf_warn_invalid_xdp_action(NULL, dst->xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(dst->dev, dst->xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		kfree_skb(skb);
		break;
	}

	return act;
}

int dev_xdp_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
		    struct net_device *dev_rx)
{
	return __xdp_enqueue(dev, xdpf, dev_rx, NULL);
}

int dev_map_enqueue(struct bpf_dtab_netdev *dst, struct xdp_frame *xdpf,
		    struct net_device *dev_rx)
{
	struct net_device *dev = dst->dev;

	return __xdp_enqueue(dev, xdpf, dev_rx, dst->xdp_prog);
}

int acceldev_map_enqueue(struct bpf_dtab_acceldev *dst, struct xdp_frame *xdpf,
			 struct net_device *dev_rx)
{
	struct bpf_acceldev_ops *ops;
	void *handle;

	if (!dst ||
	    !dst->acceldev_ops ||
		!dst->acceldev_ops->enqueue)
		return -EFAULT;

	if (batch_enabled) {
		/* Batch request */
		if (atomic_read(&dst->refcnt) == 0) {
			return __acceldev_enqueue(dst, xdpf, dev_rx, dst->xdp_prog);
		} else {
			dst->dev_rx = dev_rx;
			return acceldev_bulkq_enqueue(dst, xdpf); /* kthread on remote cpu */
		}
	} else {
		/* Single request */
		ops = dst->acceldev_ops;
		handle = dst->acceldev_handle;
		if (ops->enqueue(handle, dst, &xdpf, 1, dst->xdp_prog, dev_rx) == 1)
			return 0;
		else
			return -EFAULT;
	}
}

static bool is_valid_dst(struct bpf_dtab_netdev *obj, struct xdp_frame *xdpf)
{
	if (!obj ||
	    !obj->dev->netdev_ops->ndo_xdp_xmit)
		return false;

	if (xdp_ok_fwd_dev(obj->dev, xdp_get_frame_len(xdpf)))
		return false;

	return true;
}

static int dev_map_enqueue_clone(struct bpf_dtab_netdev *obj,
				 struct net_device *dev_rx,
				 struct xdp_frame *xdpf)
{
	struct xdp_frame *nxdpf;

	nxdpf = xdpf_clone(xdpf);
	if (!nxdpf)
		return -ENOMEM;

	bq_enqueue(obj->dev, nxdpf, dev_rx, obj->xdp_prog);

	return 0;
}

static inline bool is_ifindex_excluded(int *excluded, int num_excluded, int ifindex)
{
	while (num_excluded--) {
		if (ifindex == excluded[num_excluded])
			return true;
	}
	return false;
}

/* Get ifindex of each upper device. 'indexes' must be able to hold at
 * least MAX_NEST_DEV elements.
 * Returns the number of ifindexes added.
 */
static int get_upper_ifindexes(struct net_device *dev, int *indexes)
{
	struct net_device *upper;
	struct list_head *iter;
	int n = 0;

	netdev_for_each_upper_dev_rcu(dev, upper, iter) {
		indexes[n++] = upper->ifindex;
	}
	return n;
}

int dev_map_enqueue_multi(struct xdp_frame *xdpf, struct net_device *dev_rx,
			  struct bpf_map *map, bool exclude_ingress)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *dst, *last_dst = NULL;
	int excluded_devices[1+MAX_NEST_DEV];
	struct hlist_head *head;
	int num_excluded = 0;
	unsigned int i;
	int err;

	if (exclude_ingress) {
		num_excluded = get_upper_ifindexes(dev_rx, excluded_devices);
		excluded_devices[num_excluded++] = dev_rx->ifindex;
	}

	if (map->map_type == BPF_MAP_TYPE_DEVMAP) {
		for (i = 0; i < map->max_entries; i++) {
			dst = rcu_dereference_check(dtab->netdev_map[i],
						    rcu_read_lock_bh_held());
			if (!is_valid_dst(dst, xdpf))
				continue;

			if (is_ifindex_excluded(excluded_devices, num_excluded, dst->dev->ifindex))
				continue;

			/* we only need n-1 clones; last_dst enqueued below */
			if (!last_dst) {
				last_dst = dst;
				continue;
			}

			err = dev_map_enqueue_clone(last_dst, dev_rx, xdpf);
			if (err)
				return err;

			last_dst = dst;
		}
	} else { /* BPF_MAP_TYPE_DEVMAP_HASH */
		for (i = 0; i < dtab->n_buckets; i++) {
			head = dev_map_index_hash(dtab, i);
			hlist_for_each_entry_rcu(dst, head, index_hlist,
						 lockdep_is_held(&dtab->index_lock)) {
				if (!is_valid_dst(dst, xdpf))
					continue;

				if (is_ifindex_excluded(excluded_devices, num_excluded,
							dst->dev->ifindex))
					continue;

				/* we only need n-1 clones; last_dst enqueued below */
				if (!last_dst) {
					last_dst = dst;
					continue;
				}

				err = dev_map_enqueue_clone(last_dst, dev_rx, xdpf);
				if (err)
					return err;

				last_dst = dst;
			}
		}
	}

	/* consume the last copy of the frame */
	if (last_dst)
		bq_enqueue(last_dst->dev, xdpf, dev_rx, last_dst->xdp_prog);
	else
		xdp_return_frame_rx_napi(xdpf); /* dtab is empty */

	return 0;
}

int dev_map_generic_redirect(struct bpf_dtab_netdev *dst, struct sk_buff *skb,
			     struct bpf_prog *xdp_prog)
{
	int err;

	err = xdp_ok_fwd_dev(dst->dev, skb->len);
	if (unlikely(err))
		return err;

	/* Redirect has already succeeded semantically at this point, so we just
	 * return 0 even if packet is dropped. Helper below takes care of
	 * freeing skb.
	 */
	if (dev_map_bpf_prog_run_skb(skb, dst) != XDP_PASS)
		return 0;

	skb->dev = dst->dev;
	generic_xdp_tx(skb, xdp_prog);

	return 0;
}

static int dev_map_redirect_clone(struct bpf_dtab_netdev *dst,
				  struct sk_buff *skb,
				  struct bpf_prog *xdp_prog)
{
	struct sk_buff *nskb;
	int err;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return -ENOMEM;

	err = dev_map_generic_redirect(dst, nskb, xdp_prog);
	if (unlikely(err)) {
		consume_skb(nskb);
		return err;
	}

	return 0;
}

int dev_map_redirect_multi(struct net_device *dev, struct sk_buff *skb,
			   struct bpf_prog *xdp_prog, struct bpf_map *map,
			   bool exclude_ingress)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *dst, *last_dst = NULL;
	int excluded_devices[1+MAX_NEST_DEV];
	struct hlist_head *head;
	struct hlist_node *next;
	int num_excluded = 0;
	unsigned int i;
	int err;

	if (exclude_ingress) {
		num_excluded = get_upper_ifindexes(dev, excluded_devices);
		excluded_devices[num_excluded++] = dev->ifindex;
	}

	if (map->map_type == BPF_MAP_TYPE_DEVMAP) {
		for (i = 0; i < map->max_entries; i++) {
			dst = rcu_dereference_check(dtab->netdev_map[i],
						    rcu_read_lock_bh_held());
			if (!dst)
				continue;

			if (is_ifindex_excluded(excluded_devices, num_excluded, dst->dev->ifindex))
				continue;

			/* we only need n-1 clones; last_dst enqueued below */
			if (!last_dst) {
				last_dst = dst;
				continue;
			}

			err = dev_map_redirect_clone(last_dst, skb, xdp_prog);
			if (err)
				return err;

			last_dst = dst;

		}
	} else { /* BPF_MAP_TYPE_DEVMAP_HASH */
		for (i = 0; i < dtab->n_buckets; i++) {
			head = dev_map_index_hash(dtab, i);
			hlist_for_each_entry_safe(dst, next, head, index_hlist) {
				if (!dst)
					continue;

				if (is_ifindex_excluded(excluded_devices, num_excluded,
							dst->dev->ifindex))
					continue;

				/* we only need n-1 clones; last_dst enqueued below */
				if (!last_dst) {
					last_dst = dst;
					continue;
				}

				err = dev_map_redirect_clone(last_dst, skb, xdp_prog);
				if (err)
					return err;

				last_dst = dst;
			}
		}
	}

	/* consume the first skb and return */
	if (last_dst)
		return dev_map_generic_redirect(last_dst, skb, xdp_prog);

	/* dtab is empty */
	consume_skb(skb);
	return 0;
}

static void *dev_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab_netdev *obj = __dev_map_lookup_elem(map, *(u32 *)key);

	return obj ? &obj->val : NULL;
}

static void *dev_map_hash_lookup_elem(struct bpf_map *map, void *key)
{
	if (is_acceldev(map)) {
#if ACCELDEV_LOOKUP_ELEM_CTX_ENBALED
		u32 key_instance = GET_KEY_INSTANCE(key);
		u32 key_ctx = GET_KEY_CTX(key);
		struct bpf_dtab_acceldev *acceldev;
		struct bpf_acceldevmap_val_ctx *acceldev_ctx;

		acceldev = __acceldev_map_hash_lookup_elem(map, key_instance);
		if (!acceldev)
			return NULL;

		acceldev_ctx = __acceldev_ctx_map_hash_lookup_elem(acceldev, key_ctx);
		return acceldev_ctx ? &acceldev_ctx->acceldevmap_val : NULL;
#else
		u32 key_instance = GET_KEY_INSTANCE(key);

		struct bpf_dtab_acceldev *acceldev = __acceldev_map_hash_lookup_elem(map,
								key_instance);

		return acceldev ? &acceldev->acceldev_handle : NULL;
#endif
	} else {
		struct bpf_dtab_netdev *obj = __dev_map_hash_lookup_elem(map,
								*(u32 *)key);
		return obj ? &obj->val : NULL;
	}
}

void *dev_map_hash_lookup_acceldevmap_val(void *dev, u32 key_ctx)
{
	unsigned int sequence;
	struct bpf_dtab_acceldev *acceldev = dev;
	struct bpf_acceldevmap_val_ctx *acceldev_ctx;

	do {
		sequence = read_seqcount_begin(&acceldev->ctx_seqcount_lock);

		rcu_read_lock();
		acceldev_ctx = __acceldev_ctx_map_hash_lookup_elem(acceldev, key_ctx);
		rcu_read_unlock();
	} while ((read_seqcount_retry(&acceldev->ctx_seqcount_lock, sequence)) && (!acceldev_ctx));

	if (!acceldev_ctx)
		return NULL;

	return &acceldev_ctx->acceldevmap_val;
}
EXPORT_SYMBOL(dev_map_hash_lookup_acceldevmap_val);

void *dev_map_hash_lookup_acceldevmap_ctx(void *dev, u32 key_ctx)
{
	unsigned int sequence;
	struct bpf_dtab_acceldev *acceldev = dev;
	struct bpf_acceldevmap_val_ctx *acceldev_ctx;

	do {
		sequence = read_seqcount_begin(&acceldev->ctx_seqcount_lock);

		rcu_read_lock();
		acceldev_ctx = __acceldev_ctx_map_hash_lookup_elem(acceldev, key_ctx);
		rcu_read_unlock();
	} while ((read_seqcount_retry(&acceldev->ctx_seqcount_lock, sequence)) && (!acceldev_ctx));

	if (NULL == acceldev_ctx)
		return NULL;

	return acceldev_ctx->ctx;
}
EXPORT_SYMBOL(dev_map_hash_lookup_acceldevmap_ctx);

static void __dev_map_entry_free(struct rcu_head *rcu)
{
	struct bpf_dtab_netdev *dev;

	dev = container_of(rcu, struct bpf_dtab_netdev, rcu);
	if (dev->xdp_prog)
		bpf_prog_put(dev->xdp_prog);
	dev_put(dev->dev);
	kfree(dev);
}

static void __acceldev_map_entry_free(struct rcu_head *rcu)
{
	struct bpf_dtab_acceldev *acceldev;

	acceldev = container_of(rcu, struct bpf_dtab_acceldev, rcu);

	acceldev_destroy_instance(acceldev);

	if (acceldev->xdp_prog)
		bpf_prog_put(acceldev->xdp_prog);
	pci_dev_put(acceldev->dev);

	free_percpu(acceldev->bq);
	acceldev->bq = NULL;

	/* For simplicity, The queue must be empty at this point for test!! */
	if (atomic_dec_and_test(&acceldev->refcnt)) { // do it only in case of refcnt 1
		ptr_ring_cleanup(acceldev->queue, NULL);
		kfree(acceldev->queue);
		acceldev->queue = NULL;
		free_percpu(acceldev->bulkq);
		acceldev->bulkq = NULL;
		kthread_stop(acceldev->kthread);
	}
	kfree(acceldev);
}

static void __acceldev_map_ctx_entry_free(struct rcu_head *rcu)
{
	struct bpf_acceldevmap_val_ctx *ctx;

	ctx = container_of(rcu, struct bpf_acceldevmap_val_ctx, rcu);

	if (ctx->acceldev_ops &&
	    ctx->acceldev_ops->destroy_ctx)
		ctx->acceldev_ops->destroy_ctx(ctx->acceldev_handle, ctx->ctx);

	kfree(ctx);
}

static void __acceldev_map_ctx_entry_free_without_destory(struct rcu_head *rcu)
{
	struct bpf_acceldevmap_val_ctx *acceldev_ctx;

	acceldev_ctx = container_of(rcu, struct bpf_acceldevmap_val_ctx, rcu);

	kfree(acceldev_ctx);
}

static int dev_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *old_dev;
	int k = *(u32 *)key;

	if (k >= map->max_entries)
		return -EINVAL;

	old_dev = unrcu_pointer(xchg(&dtab->netdev_map[k], NULL));
	if (old_dev)
		call_rcu(&old_dev->rcu, __dev_map_entry_free);
	return 0;
}

static int dev_map_hash_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	unsigned long flags;
	int ret = -ENOENT;

	if (DTAB_STYLE_IS_ACCELDEV(dtab)) {
		struct bpf_dtab_acceldev *odev;
		struct bpf_acceldevmap_val_ctx *octx;
		u32 key_instance = GET_KEY_INSTANCE(key);
		u32 key_ctx = GET_KEY_CTX(key);

		spin_lock_irqsave(&dtab->index_lock, flags);
		odev = __acceldev_map_hash_lookup_elem(map, key_instance);
		if (odev) {
			octx = __acceldev_ctx_map_hash_lookup_elem(odev, key_ctx);
			if (octx) {
				spin_lock_bh(&odev->ctx_lock);

				odev->ctx_items--;
				hlist_del_rcu(&octx->index_hlist);

				call_rcu(&octx->rcu, __acceldev_map_ctx_entry_free);
				ret = 0;

				/* Delete accledev if instance doesn't have any ctx anymore. */
				if (odev->ctx_items == 0)
					call_rcu(&odev->rcu, __acceldev_map_entry_free);


				/* Due to caller map_hash_delete_elem() disable
				 * preemption, cannot call kthread_stop() to make sure queue is empty.
				 * Instead a work_queue is started for stopping kthread,
				 * acceldev_map_kthread_stop, which waits for an RCU grace period before
				 * stopping kthread, emptying the queue.
				 * Not implemented yet!!!
				 */

				spin_unlock_bh(&odev->ctx_lock);
			}
		}
		spin_unlock_irqrestore(&dtab->index_lock, flags);
	} else {
		struct bpf_dtab_netdev *old_dev;
		int k = *(u32 *)key;

		spin_lock_irqsave(&dtab->index_lock, flags);

		old_dev = __dev_map_hash_lookup_elem(map, k);
		if (old_dev) {
			dtab->items--;
			hlist_del_rcu(&old_dev->index_hlist);
			call_rcu(&old_dev->rcu, __dev_map_entry_free);
			ret = 0;
		}
		spin_unlock_irqrestore(&dtab->index_lock, flags);
	}

	return ret;
}

struct hlist_head *acceldev_ctx_hash_alloc(unsigned int sz)
{
	struct hlist_head *n;

	if (sz <= PAGE_SIZE)
		n = kzalloc(sz, GFP_KERNEL);
	else if (hashdist)
		n = vzalloc(sz);
	else
		n = (struct hlist_head *)
			__get_free_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
					 get_order(sz));

	return n;
}

static unsigned long acceldev_ctx_hash_new_size(unsigned int state_hmask)
{
	return ((state_hmask + 1) << 1) * sizeof(struct hlist_head);
}

static void ctx_hash_transfer(struct hlist_head *list,
			      struct hlist_head *ctx_list,
			       unsigned int nhashmask)
{
	struct hlist_node *tmp;
	struct bpf_acceldevmap_val_ctx *acceldev_ctx;

	hlist_for_each_entry_safe(acceldev_ctx, tmp, list, index_hlist) {
		unsigned int h;

		h = acceldev_ctx_map_index_hash_with_mask(acceldev_ctx->idx, nhashmask);
		hlist_add_head_rcu(&acceldev_ctx->index_hlist, ctx_list + h);
	}
}

static void acceldev_ctx_hash_resize(struct work_struct *work)
{
	struct bpf_dtab_acceldev *dev;
	struct hlist_head *ndst, *odst;
	unsigned long nsize, osize;
	unsigned int nhashmask, ohashmask;
	int i;

	dev = container_of(work, struct bpf_dtab_acceldev, ctx_hash_work);
	nsize = acceldev_ctx_hash_new_size(BUCKET_TO_HMASK(dev->ctx_n_buckets));
	ndst = acceldev_ctx_hash_alloc(nsize);
	if (!ndst)
		return;

	spin_lock_bh(&dev->ctx_lock);
	write_seqcount_begin(&dev->ctx_seqcount_lock);

	nhashmask = (nsize / sizeof(struct hlist_head)) - 1U;
	odst = rcu_dereference_protected(dev->ctx_idx_head, lockdep_is_held(&dev->ctx_lock));

	for (i = BUCKET_TO_HMASK(dev->ctx_n_buckets); i >= 0; i--)
		ctx_hash_transfer(odst + i, ndst, nhashmask);

	ohashmask = BUCKET_TO_HMASK(dev->ctx_n_buckets);

	rcu_assign_pointer(dev->ctx_idx_head, ndst);
	dev->ctx_n_buckets = HMASK_TO_BUCKET(nhashmask);

	write_seqcount_end(&dev->ctx_seqcount_lock);
	spin_unlock_bh(&dev->ctx_lock);

	osize = (ohashmask + 1) * sizeof(struct hlist_head);

	synchronize_rcu();

	acceldev_ctx_hash_free(odst, osize);
}

static struct bpf_dtab_acceldev *__acceldev_map_alloc_node(struct bpf_dtab *dtab,
							   struct bpf_acceldevmap_val *val,
						    unsigned int idx)
{
	struct bpf_prog *prog = NULL;
	struct bpf_dtab_acceldev *acceldev;
	struct bpf_acceldev_ops_data *ops;
	int err;
	int sz = sizeof(struct hlist_head) * ACCELDEV_CTX_BUCKET;
	int cpu;
	unsigned int devfn;

	acceldev = bpf_map_kmalloc_node(&dtab->map, sizeof(*acceldev),
					GFP_NOWAIT | __GFP_NOWARN,
				   dtab->map.numa_node);
	if (!acceldev)
		return ERR_PTR(-ENOMEM);

	acceldev->bq = alloc_percpu(struct xdp_acceldev_bulk_queue);
	if (!acceldev->bq)
		goto err_out;

	for_each_possible_cpu(cpu) {
		per_cpu_ptr(acceldev->bq, cpu)->acceldev = acceldev;
		per_cpu_ptr(acceldev->bq, cpu)->count = 0;
	}

	acceldev->ctx_idx_head = acceldev_ctx_hash_alloc(sz);
	if (!acceldev->ctx_idx_head)
		goto err_out;

	/* Get pci_dev by bdf */
	devfn = PCI_DEVFN(PCI_SLOT(val->bdfn), PCI_FUNC(val->bdfn));
	acceldev->dev = pci_get_domain_bus_and_slot(0, ((val->bdfn >> 8) & 0xFF), devfn);
	if (!acceldev->dev) {
		err = -EINVAL;
		goto err_out;
	}

	if (val->bpf_prog.fd > 0) {
		prog = bpf_prog_get_type_dev(val->bpf_prog.fd,
					     BPF_PROG_TYPE_XDP, false);
		if (IS_ERR(prog)) {
			err = -EINVAL;
			goto err_put_dev;
		}
	}

	acceldev->idx = idx;
	acceldev->dtab = dtab;
	acceldev->acceldev_type = val->acceldev_type;

	/* acceldev_ctx hash init */
	acceldev->ctx_n_buckets = sz / sizeof(struct hlist_head);
	acceldev->ctx_items = 0;
	INIT_WORK(&acceldev->ctx_hash_work, acceldev_ctx_hash_resize);
	spin_lock_init(&acceldev->ctx_lock);
	seqcount_spinlock_init(&acceldev->ctx_seqcount_lock, &acceldev->ctx_lock);

	/* check acceldev_ops_data_list and set pci_dev */
	acceldev->acceldev_ops = NULL;

	atomic_set(&acceldev->refcnt, 0);

	rcu_read_lock();
	list_for_each_entry_rcu(ops, &acceldev_ops_data_list, list) {
		if (ops->acceldev_ops.acceldev_type == acceldev->acceldev_type &&
		    ops->acceldev_ops.dev == acceldev->dev) {
			acceldev->acceldev_ops = &ops->acceldev_ops;
		}
	}
	rcu_read_unlock();
	acceldev->acceldev_handle = NULL;

	/* bpf_acceldevmap_val set in acceldev_ctx */
	if (prog)
		acceldev->xdp_prog = prog;
	else
		acceldev->xdp_prog = NULL;

	return acceldev;

err_put_dev:
	pci_dev_put(acceldev->dev);

err_out:
	kfree(acceldev);
	return ERR_PTR(err);
}

static void acceldev_ctx_hash_grow_check(struct bpf_dtab_acceldev *acceldev, bool have_collision)
{
	if (have_collision &&
	    (BUCKET_TO_HMASK(acceldev->ctx_n_buckets) + 1) < ACCELDEV_CTX_HASHMAX &&
		acceldev->ctx_items > BUCKET_TO_HMASK(acceldev->ctx_n_buckets)) {
		schedule_work(&acceldev->ctx_hash_work);
	}
}

static struct bpf_acceldevmap_val_ctx *__acceldev_ctx_alloc(struct bpf_dtab_acceldev *dev,
							    struct bpf_acceldevmap_val *val,
	unsigned int idx)
{
	struct bpf_acceldevmap_val_ctx *ctx;
	unsigned int sz;
	struct bpf_acceldev_ops *ops;

	if (!dev)
		return ERR_PTR(-EINVAL);

	sz = sizeof(*ctx) + val->acceldata_sz;
	ctx = bpf_map_kmalloc_node(&dev->dtab->map, sz,
				   GFP_NOWAIT | __GFP_NOWARN,
				   dev->dtab->map.numa_node);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->idx = idx;
	ops = dev->acceldev_ops;

	if (ops)
		ctx->acceldev_ops = ops;

	sz = sizeof(struct bpf_acceldevmap_val) + val->acceldata_sz;
	memcpy((void *)(&ctx->acceldevmap_val), val, sz);

	if (dev->xdp_prog)
		ctx->acceldevmap_val.bpf_prog.id = dev->xdp_prog->aux->id;
	else
		ctx->acceldevmap_val.bpf_prog.id = 0;

	if (!dev->acceldev_handle) {
		if (ops &&
		    ops->create_instance) {
			dev->acceldev_handle = ops->create_instance(&ctx->acceldevmap_val);
			if (IS_ERR(dev->acceldev_handle))
				return ERR_PTR(-EINVAL);
		} else {
		}
	} else {
	}

	if (ops &&
	    ops->create_ctx) {
		ctx->ctx = ops->create_ctx(dev->acceldev_handle, &ctx->acceldevmap_val);
		if (IS_ERR(ctx->ctx)) {
			kfree(ctx);
			return ERR_PTR(-EINVAL);
		}
		ctx->acceldev_handle = dev->acceldev_handle;
	}

	return ctx;
}

static struct bpf_dtab_netdev *__dev_map_alloc_node(struct net *net,
						    struct bpf_dtab *dtab,
						    struct bpf_devmap_val *val,
						    unsigned int idx)
{
	struct bpf_prog *prog = NULL;
	struct bpf_dtab_netdev *dev;

	dev = bpf_map_kmalloc_node(&dtab->map, sizeof(*dev),
				   GFP_NOWAIT | __GFP_NOWARN,
				   dtab->map.numa_node);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	dev->dev = dev_get_by_index(net, val->ifindex);
	if (!dev->dev)
		goto err_out;

	if (val->bpf_prog.fd > 0) {
		prog = bpf_prog_get_type_dev(val->bpf_prog.fd,
					     BPF_PROG_TYPE_XDP, false);
		if (IS_ERR(prog))
			goto err_put_dev;
		if (prog->expected_attach_type != BPF_XDP_DEVMAP ||
		    !bpf_prog_map_compatible(&dtab->map, prog))
			goto err_put_prog;
	}

	dev->idx = idx;
	dev->dtab = dtab;
	if (prog) {
		dev->xdp_prog = prog;
		dev->val.bpf_prog.id = prog->aux->id;
	} else {
		dev->xdp_prog = NULL;
		dev->val.bpf_prog.id = 0;
	}
	dev->val.ifindex = val->ifindex;

	return dev;
err_put_prog:
	bpf_prog_put(prog);
err_put_dev:
	dev_put(dev->dev);
err_out:
	kfree(dev);
	return ERR_PTR(-EINVAL);
}

static int __dev_map_update_elem(struct net *net, struct bpf_map *map,
				 void *key, void *value, u64 map_flags)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *dev, *old_dev;
	struct bpf_devmap_val val = {};
	u32 i = *(u32 *)key;

	if (unlikely(map_flags > BPF_EXIST))
		return -EINVAL;
	if (unlikely(i >= dtab->map.max_entries))
		return -E2BIG;
	if (unlikely(map_flags == BPF_NOEXIST))
		return -EEXIST;

	/* already verified value_size <= sizeof val */
	memcpy(&val, value, map->value_size);

	if (!val.ifindex) {
		dev = NULL;
		/* can not specify fd if ifindex is 0 */
		if (val.bpf_prog.fd > 0)
			return -EINVAL;
	} else {
		dev = __dev_map_alloc_node(net, dtab, &val, i);
		if (IS_ERR(dev))
			return PTR_ERR(dev);
	}

	/* Use call_rcu() here to ensure rcu critical sections have completed
	 * Remembering the driver side flush operation will happen before the
	 * net device is removed.
	 */
	old_dev = unrcu_pointer(xchg(&dtab->netdev_map[i], RCU_INITIALIZER(dev)));
	if (old_dev)
		call_rcu(&old_dev->rcu, __dev_map_entry_free);

	return 0;
}

static int dev_map_update_elem(struct bpf_map *map, void *key, void *value,
			       u64 map_flags)
{
	return __dev_map_update_elem(current->nsproxy->net_ns,
				     map, key, value, map_flags);
}

static int __acceldev_map_hash_update_elem(struct bpf_map *map,
					   void *key, void *value, u64 map_flags)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_acceldev *ndev = NULL;
	struct bpf_dtab_acceldev *odev = NULL;
	struct bpf_acceldevmap_val_ctx *nctx = NULL;
	struct bpf_acceldevmap_val_ctx *octx = NULL;
	struct bpf_acceldevmap_val *acceldev_val = NULL;
	u32 key_instance = GET_KEY_INSTANCE(key);
	u32 key_ctx = GET_KEY_CTX(key);
	unsigned long flags;
	int err = -EEXIST;
	struct bpf_prog *prog = NULL;
	int cpu, i;
	bool collision = false;
	int numa;
	gfp_t gfp = GFP_KERNEL | __GFP_NOWARN;

	acceldev_val = (struct bpf_acceldevmap_val *)value;

	/* already verified value_size <= sizeof val */
	if (unlikely(map_flags > BPF_EXIST || !acceldev_val || acceldev_val->bdfn == 0))
		return -EINVAL;

	spin_lock_irqsave(&dtab->index_lock, flags);

	odev = __acceldev_map_hash_lookup_elem(map, key_instance);
	if (odev && (map_flags & BPF_NOEXIST))
		goto out_err;

	/* Instance found */
	if (odev) {
		octx = __acceldev_ctx_map_hash_lookup_elem(odev, key_ctx);
		if (octx && (map_flags & BPF_NOEXIST))
			goto out_err_ctx_locked;

		/* Ctx found */
		if (octx) {
			spin_lock_bh(&odev->ctx_lock);

			/* Create new ctx */
			nctx = __acceldev_ctx_alloc(odev, acceldev_val, key_ctx);
			if (IS_ERR(nctx)) {
				err = PTR_ERR(nctx);
				spin_unlock_bh(&odev->ctx_lock);
				goto out_err_ctx_locked;
			}

			/* Delete old ctx from hlist */
			hlist_del_rcu(&octx->index_hlist);

			/* Add new ctx into hlist */
			hlist_add_head_rcu(&nctx->index_hlist,
					   acceldev_ctx_map_index_hash(odev, key_ctx));

			/* Free old ctx */
			call_rcu(&octx->rcu, __acceldev_map_ctx_entry_free);

			spin_unlock_bh(&odev->ctx_lock);
		} else {
			/* Ctx not found */
			spin_lock_bh(&odev->ctx_lock);

			/* Create new ctx */
			nctx = __acceldev_ctx_alloc(odev, acceldev_val, key_ctx);
			if (IS_ERR(nctx)) {
				err = PTR_ERR(nctx);
				spin_unlock_bh(&odev->ctx_lock);
				goto out_err_ctx_locked;
			}

			/* Add new ctx into hlist */
			hlist_add_head_rcu(&nctx->index_hlist,
					   acceldev_ctx_map_index_hash(odev, key_ctx));

			/* Ctx item++ */
			odev->ctx_items++;
			spin_unlock_bh(&odev->ctx_lock);
			if (nctx->index_hlist.next)
				collision = true;
			acceldev_ctx_hash_grow_check(odev, collision);
		}

		/* Create new instance */
		/* Don't call __acceldev_map_alloc_node() because no need to init again. */
		ndev = bpf_map_kmalloc_node(&dtab->map, sizeof(*ndev), GFP_NOWAIT | __GFP_NOWARN,
					    dtab->map.numa_node);
		if (!ndev)
			return -ENOMEM;

		/* Update new instance here(xdp_prog) */
		memcpy(ndev, odev, sizeof(*ndev));

		for_each_possible_cpu(cpu) {
			per_cpu_ptr(ndev->bq, cpu)->acceldev = ndev;
		}

		if (acceldev_val->bpf_prog.fd > 0) {
			prog = bpf_prog_get_type_dev(acceldev_val->bpf_prog.fd,
						     BPF_PROG_TYPE_XDP, false);
		}

		if (prog)
			ndev->xdp_prog = prog;
		else
			ndev->xdp_prog = NULL;

		/* Delete old instance from hlist */
		hlist_del_rcu(&odev->index_hlist);

		/* Add new instance into hlist */
		hlist_add_head_rcu(&ndev->index_hlist,
				   dev_map_index_hash(dtab, key_instance));

		if (odev->xdp_prog)
			bpf_prog_put(odev->xdp_prog);

		call_rcu(&odev->rcu, __acceldev_entry_free_no_destory);
		spin_unlock_irqrestore(&dtab->index_lock, flags);
	} else {
		/* Instance not found */
		/* Create new instance */
		if (dtab->items >= dtab->map.max_entries) {
			err = -E2BIG;
			goto out_err;
		}

		ndev = __acceldev_map_alloc_node(dtab, acceldev_val, key_instance);
		if (IS_ERR(ndev)) {
			err = PTR_ERR(ndev);
			goto out_err;
		}

		/* Add new instance into hlist */
		hlist_add_head_rcu(&ndev->index_hlist,
				   dev_map_index_hash(dtab, key_instance));


		/* Instance item++ */
		dtab->items++;
		spin_unlock_irqrestore(&dtab->index_lock, flags);

		/* Create new ctx */
		nctx = __acceldev_ctx_alloc(ndev, acceldev_val, key_ctx);
		if (IS_ERR(nctx)) {
			err = PTR_ERR(nctx);
			spin_unlock_bh(&ndev->ctx_lock);
			goto out_err_ctx_locked;
		}

		/* Add new ctx into hlist */
		spin_lock_bh(&ndev->ctx_lock);
		hlist_add_head_rcu(&nctx->index_hlist,
				   acceldev_ctx_map_index_hash(ndev, key_ctx));

		/* Ctx item++ */
		ndev->ctx_items++;
		spin_unlock_bh(&ndev->ctx_lock);

		if (nctx->index_hlist.next)
			collision = true;
		acceldev_ctx_hash_grow_check(odev, collision);

		/* duplicate protection */
		if (atomic_read(&ndev->refcnt) > 0 ||
		    acceldev_val->cpu == 0) /* NIC IRQ on CPU 0 by default*/
			return 0;

		/* Alloc percpu bulkq */
		ndev->bulkq = bpf_map_alloc_percpu(map, sizeof(*ndev->bulkq),
					   sizeof(void *), gfp);
		if (!ndev->bulkq)
			goto out_err;

		for_each_possible_cpu(i) {
			per_cpu_ptr(ndev->bulkq, i)->obj = ndev;
			per_cpu_ptr(ndev->bulkq, i)->count = 0;
		}

		/* Have map->numa_node, but choose node of redirect target CPU */
		numa = cpu_to_node(acceldev_val->cpu);

		/* Alloc queue */
		ndev->queue = bpf_map_kmalloc_node(map, sizeof(*ndev->queue), gfp, numa);
		if (!ndev->queue)
			goto free_bulkq;

		err = ptr_ring_init(ndev->queue, acceldev_val->qsize, gfp);
		if (err)
			goto free_queue;

		ndev->cpu = acceldev_val->cpu;
		//ndev->map_id = map->id;

		/* Setup kthread */
		ndev->kthread = kthread_create_on_node(acceldev_map_kthread_run, ndev, numa,
						       "acceldevmap/on/cpu%d", ndev->cpu);
		if (IS_ERR(ndev->kthread))
			goto free_queue;

		atomic_inc(&ndev->refcnt); /* 1-refcnt for kthread */

		/* Make sure kthread runs on a single CPU */
		kthread_bind(ndev->kthread, ndev->cpu);
		wake_up_process(ndev->kthread);
	}

	return 0;

free_queue:
	kfree(ndev->queue);

free_bulkq:
	free_percpu(ndev->bulkq);

out_err_ctx_locked:

out_err:
	spin_unlock_irqrestore(&dtab->index_lock, flags);

	if (nctx && !IS_ERR(nctx) && octx)
		call_rcu(&nctx->rcu, __acceldev_map_ctx_entry_free_without_destory);

	if (nctx && !IS_ERR(nctx) && !octx)
		call_rcu(&nctx->rcu, __acceldev_map_ctx_entry_free);

	if (ndev && !IS_ERR(ndev) && odev)
		call_rcu(&ndev->rcu, __acceldev_entry_free_no_destory);

	if (ndev && !IS_ERR(ndev) && !odev)
		call_rcu(&ndev->rcu, __acceldev_map_entry_free);

	return err;
}

static long __dev_map_hash_update_elem(struct net *net, struct bpf_map *map,
				       void *key, void *value, u64 map_flags)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *dev, *old_dev;
	struct bpf_devmap_val val = {};
	u32 idx = *(u32 *)key;
	unsigned long flags;
	int err = -EEXIST;

	/* already verified value_size <= sizeof val */
	memcpy(&val, value, map->value_size);

	if (unlikely(map_flags > BPF_EXIST || !val.ifindex))
		return -EINVAL;

	spin_lock_irqsave(&dtab->index_lock, flags);

	old_dev = __dev_map_hash_lookup_elem(map, idx);
	if (old_dev && (map_flags & BPF_NOEXIST))
		goto out_err;

	dev = __dev_map_alloc_node(net, dtab, &val, idx);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out_err;
	}

	if (old_dev) {
		hlist_del_rcu(&old_dev->index_hlist);
	} else {
		if (dtab->items >= dtab->map.max_entries) {
			spin_unlock_irqrestore(&dtab->index_lock, flags);
			call_rcu(&dev->rcu, __dev_map_entry_free);
			return -E2BIG;
		}
		dtab->items++;
	}

	hlist_add_head_rcu(&dev->index_hlist,
			   dev_map_index_hash(dtab, idx));
	spin_unlock_irqrestore(&dtab->index_lock, flags);

	if (old_dev)
		call_rcu(&old_dev->rcu, __dev_map_entry_free);

	return 0;

out_err:
	spin_unlock_irqrestore(&dtab->index_lock, flags);
	return err;
}

static int dev_map_hash_update_elem(struct bpf_map *map, void *key, void *value,
				   u64 map_flags)
{
	if (is_acceldev(map))
		return __acceldev_map_hash_update_elem(map, key, value, map_flags);

	return __dev_map_hash_update_elem(current->nsproxy->net_ns,
					 map, key, value, map_flags);
}

static int dev_map_redirect(struct bpf_map *map, u64 ifindex, u64 flags)
{
	return __bpf_xdp_redirect_map(map, ifindex, flags,
				      BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS,
				      __dev_map_lookup_elem);
}

static int dev_hash_map_redirect(struct bpf_map *map, u64 ifindex, u64 flags)
{
	if (is_acceldev(map)) {
		return __bpf_xdp_redirect_map(map, ifindex, flags,
				      BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS,
				      __acceldev_map_hash_lookup_elem);
	}

	return __bpf_xdp_redirect_map(map, ifindex, flags,
				      BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS,
				      __dev_map_hash_lookup_elem);
}

BTF_ID_LIST_SINGLE(dev_map_btf_ids, struct, bpf_dtab)
const struct bpf_map_ops dev_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = dev_map_alloc,
	.map_free = dev_map_free,
	.map_get_next_key = dev_map_get_next_key,
	.map_lookup_elem = dev_map_lookup_elem,
	.map_update_elem = dev_map_update_elem,
	.map_delete_elem = dev_map_delete_elem,
	.map_check_btf = map_check_no_btf,
	.map_btf_id = &dev_map_btf_ids[0],
	.map_redirect = dev_map_redirect,
};

const struct bpf_map_ops dev_map_hash_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = dev_map_alloc,
	.map_free = dev_map_free,
	.map_get_next_key = dev_map_hash_get_next_key,
	.map_lookup_elem = dev_map_hash_lookup_elem,
	.map_update_elem = dev_map_hash_update_elem,
	.map_delete_elem = dev_map_hash_delete_elem,
	.map_check_btf = map_check_no_btf,
	.map_btf_id = &dev_map_btf_ids[0],
	.map_redirect = dev_hash_map_redirect,
};

static void dev_map_hash_remove_netdev(struct bpf_dtab *dtab,
				       struct net_device *netdev)
{
	unsigned long flags;
	u32 i;

	spin_lock_irqsave(&dtab->index_lock, flags);
	for (i = 0; i < dtab->n_buckets; i++) {
		struct bpf_dtab_netdev *dev;
		struct hlist_head *head;
		struct hlist_node *next;

		head = dev_map_index_hash(dtab, i);

		hlist_for_each_entry_safe(dev, next, head, index_hlist) {
			if (netdev != dev->dev)
				continue;

			dtab->items--;
			hlist_del_rcu(&dev->index_hlist);
			call_rcu(&dev->rcu, __dev_map_entry_free);
		}
	}
	spin_unlock_irqrestore(&dtab->index_lock, flags);
}

static int dev_map_notification(struct notifier_block *notifier,
				ulong event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct bpf_dtab *dtab;
	int i, cpu;

	switch (event) {
	case NETDEV_REGISTER:
		if (!netdev->netdev_ops->ndo_xdp_xmit || netdev->xdp_bulkq)
			break;

		/* will be freed in free_netdev() */
		netdev->xdp_bulkq = alloc_percpu(struct xdp_dev_bulk_queue);
		if (!netdev->xdp_bulkq)
			return NOTIFY_BAD;

		for_each_possible_cpu(cpu)
			per_cpu_ptr(netdev->xdp_bulkq, cpu)->dev = netdev;
		break;
	case NETDEV_UNREGISTER:
		/* This rcu_read_lock/unlock pair is needed because
		 * dev_map_list is an RCU list AND to ensure a delete
		 * operation does not free a netdev_map entry while we
		 * are comparing it against the netdev being unregistered.
		 */
		rcu_read_lock();
		list_for_each_entry_rcu(dtab, &dev_map_list, list) {
			if (dtab->map.map_type == BPF_MAP_TYPE_DEVMAP_HASH) {
				dev_map_hash_remove_netdev(dtab, netdev);
				continue;
			}

			for (i = 0; i < dtab->map.max_entries; i++) {
				struct bpf_dtab_netdev *dev, *odev;

				dev = rcu_dereference(dtab->netdev_map[i]);
				if (!dev || netdev != dev->dev)
					continue;
				odev = unrcu_pointer(cmpxchg(&dtab->netdev_map[i], RCU_INITIALIZER(dev), NULL));
				if (dev == odev)
					call_rcu(&dev->rcu,
						 __dev_map_entry_free);
			}
		}
		rcu_read_unlock();
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block dev_map_notifier = {
	.notifier_call = dev_map_notification,
};

static int __init dev_map_init(void)
{
	int cpu;

	/* Assure tracepoint shadow struct _bpf_dtab_netdev is in sync */
	BUILD_BUG_ON(offsetof(struct bpf_dtab_netdev, dev) !=
		     offsetof(struct _bpf_dtab_netdev, dev));
	register_netdevice_notifier(&dev_map_notifier);

	for_each_possible_cpu(cpu) {
		INIT_LIST_HEAD(&per_cpu(dev_flush_list, cpu));
		INIT_LIST_HEAD(&per_cpu(acceldev_flush_list, cpu));
		INIT_LIST_HEAD(&per_cpu(acceldev_flush_list_on_rcpu, cpu));
	}
	return 0;
}

subsys_initcall(dev_map_init);

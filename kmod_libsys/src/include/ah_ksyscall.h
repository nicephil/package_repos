#ifndef _AH_KSYSCALL_H_
#define _AH_KSYSCALL_H_

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#include <net/net_namespace.h>
#endif

#if defined(AH_SUPPORT_IPV6)
#include <net/ndisc.h>
#endif

/*  void *ah_kmalloc(size_t size) */
#define ah_kmalloc(size)    kmalloc(size, GFP_KERNEL)

#define ah_kcalloc(size)    kcalloc(1, size, GFP_KERNEL)

/*  void *ah_kmalloc_atomic(size_t size) */
#define ah_kmalloc_atomic(size) kmalloc(size, GFP_ATOMIC)

/*  void *ah_kmalloc_atomic(size_t size) */
#define ah_kcalloc_atomic(size) kcalloc(1, size, GFP_ATOMIC)

/* void ah_kfree(size_t size) */
#define ah_kfree(obj)       kfree(obj)
/* kmem cache type */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define ah_kmem_cache_t     kmem_cache_t
#else
typedef struct kmem_cache        ah_kmem_cache_t;
#endif
/* API to create a slab cache */
/* ah_kmem_cache_t *ah_kmem_cache_create(char *name, size_t objsize) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define ah_kmem_cache_create(name, objsize) \
	kmem_cache_create(name, objsize, 0, 0, NULL, NULL)
#else
#define ah_kmem_cache_create(name, objsize) \
	kmem_cache_create(name, objsize, 0, 0, NULL)
#endif

/* API to destroy a slab cache */
/* int ah_kmem_cache_destroy(ah_kmem_cache_t *cachep) */
#define ah_kmem_cache_destroy(cachep) \
	kmem_cache_destroy(cachep)

/* API to alloc an object from a slab cache */
/* void *ah_kmem_cache_alloc(ah_kmem_cache_t *cachep) */
#define ah_kmem_cache_alloc(cachep) \
	kmem_cache_alloc(cachep, GFP_KERNEL)

/* API to alloc an object atomically from a slab cache */
/* Used from bottom half or interrupt context */
/* void *ah_kmem_cache_alloc_atomic(ah_kmem_cache_t *cachep) */
#define ah_kmem_cache_alloc_atomic(cachep) \
	kmem_cache_alloc(cachep, GFP_ATOMIC)

/* API to free an object to a slab cache */
/* void ah_kmem_cache_free(ah_kmem_cache_t *cachep, void *objp) */
#define ah_kmem_cache_free(cachep, objp) \
	kmem_cache_free(cachep, objp)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define ah_dev_get_by_index(ifindex) \
	dev_get_by_index(ifindex)
#define __ah_dev_get_by_index(ifindex) \
	__dev_get_by_index(ifindex)
#define ah_dev_get_by_name(name) \
	dev_get_by_name(name)
#define __ah_dev_get_by_name(name) \
	__dev_get_by_name(name)
#define ah_get_skb_input_dev(skb) \
	(skb)->input_dev
#define ah_set_skb_input_dev(skb, indev) \
	(skb)->input_dev = indev
#define ah_skb_linearize(skb) \
	skb_linearize(skb, GFP_ATOMIC)
#define ah_compare_ether_addr(addr1, addr2) \
	compare_ether_addr(addr1, addr2)
extern int arp_req_get (struct arpreq *r, struct net_device *dev);
extern int arp_req_set (struct arpreq *r, struct net_device *dev);
extern int arp_req_delete (struct arpreq *r, struct net_device *dev);
#define ah_arp_req_set(r, dev) \
	arp_req_set(r, dev)
#define ah_arp_req_delete(r, dev) \
	arp_req_delete(r, dev)

#elif  LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#define ah_dev_get_by_index(ifindex) \
	dev_get_by_index(&init_net, ifindex)
#define __ah_dev_get_by_index(ifindex) \
	__dev_get_by_index(&init_net, ifindex)
#define ah_dev_get_by_name(name) \
	dev_get_by_name(&init_net, name)
#define __ah_dev_get_by_name(name) \
	__dev_get_by_name(&init_net, name)
#define ah_get_skb_input_dev(skb) \
	__ah_dev_get_by_index((skb)->skb_iif)
#define ah_set_skb_input_dev(skb, indev) \
	(skb)->skb_iif = indev->ifindex
#define ah_skb_linearize(skb) \
	skb_linearize(skb)
#define ah_compare_ether_addr(addr1, addr2) \
	compare_ether_addr_64bits(addr1, addr2)
extern int arp_req_get (struct arpreq *r, struct net_device *dev);
extern int arp_req_set (struct net *net, struct arpreq *r, struct net_device *dev);
extern int arp_req_delete (struct net *net, struct arpreq *r, struct net_device *dev);
#define ah_arp_req_set(r, dev) \
	arp_req_set(&init_net, r, dev)
#define ah_arp_req_delete(r, dev) \
	arp_req_delete(&init_net, r, dev)

#else
#define ah_dev_get_by_index(ifindex) \
	dev_get_by_index(&init_net, ifindex)
#define __ah_dev_get_by_index(ifindex) \
	__dev_get_by_index(&init_net, ifindex)
#define ah_dev_get_by_name(name) \
	dev_get_by_name(&init_net, name)
#define __ah_dev_get_by_name(name) \
	__dev_get_by_name(&init_net, name)
#define ah_get_skb_input_dev(skb) \
	__ah_dev_get_by_index((skb)->iif)
#define ah_set_skb_input_dev(skb, indev) \
	(skb)->iif = indev->ifindex
#define ah_skb_linearize(skb) \
	skb_linearize(skb)
#define ah_compare_ether_addr(addr1, addr2) \
	compare_ether_addr_64bits(addr1, addr2)
extern int arp_req_get (struct arpreq *r, struct net_device *dev);
extern int arp_req_set (struct net *net, struct arpreq *r, struct net_device *dev);
extern int arp_req_delete (struct net *net, struct arpreq *r, struct net_device *dev);
#define ah_arp_req_set(r, dev) \
	arp_req_set(&init_net, r, dev)
#define ah_arp_req_delete(r, dev) \
	arp_req_delete(&init_net, r, dev)
#endif

#if defined(AH_SUPPORT_IPV6)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define ndp_req_get(r, dev)         0
#define ndp_req_set(net, r, dev)    0
#define ndp_req_delete(net, r, dev) 0
#define ah_ndp_req_set(r, dev)      0
#define ah_ndp_req_delete(r, dev)   0
#else
extern int ndp_req_get (struct ndpreq *r, struct net_device *dev);
extern int ndp_req_set (struct net *net, struct ndpreq *r, struct net_device *dev);
extern int ndp_req_delete (struct net *net, struct ndpreq *r, struct net_device *dev);
#define ah_ndp_req_set(r, dev) \
	ndp_req_set(&init_net, r, dev)
#define ah_ndp_req_delete(r, dev) \
	ndp_req_delete(&init_net, r, dev)
#endif
#endif

extern unsigned ah_debug_mask;
#define AH_DEBUG_WIFI_NODE 0x00000001

#ifdef CONFIG_NETFILTER
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define ah_get_skb_fw_mark(skb) \
	(skb)->nfmark
#define ah_set_skb_fw_mark(skb, value) \
	(skb)->nfmark = (value)
#else
#define ah_get_skb_fw_mark(skb) \
	(skb)->mark
#define ah_set_skb_fw_mark(skb, value) \
	(skb)->mark = (value)
#define ah_set_skb_fw_mark_ifnameidx(skb, value) \
	(skb)->mark |= (value << 8)
#endif
#endif

#endif /* _AH_KSYSCALL_H_ */


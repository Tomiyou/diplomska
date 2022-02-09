#include <linux/if_ether.h>
#include <net/netfilter/nf_conntrack_timeout.h>

struct xfe_tuple {
	unsigned short ethertype;
	unsigned char proto;
	union {
		struct in_addr in;
	} src_saddr;
	union {
		struct in_addr in;
	} dst_saddr;
	unsigned short sport;
	unsigned short dport;
	unsigned char smac[ETH_ALEN];
	unsigned char dmac[ETH_ALEN];
};

#define xfe_define_post_routing_hook(FN_NAME, HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN) \
static unsigned int FN_NAME(void *priv, \
			    struct sk_buff *SKB, \
			    const struct nf_hook_state *state)

#define xfe_ipv4_post_routing_hook(HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN) \
	xfe_define_post_routing_hook(__xfe_ipv4_post_routing_hook, HOOKNUM, OPS, SKB, UNUSED, OUT, OKFN)

#define XFE_IPV4_NF_POST_ROUTING_HOOK(fn) \
	{						\
		.hook = fn,				\
		.pf = NFPROTO_IPV4,			\
		.hooknum = NF_INET_POST_ROUTING,	\
		.priority = NF_IP_PRI_NAT_SRC + 1,	\
	}

#define XFE_NF_CT_DEFAULT_ZONE (&nf_ct_zone_dflt)

/*
 * xfe_dev_get_master
 * 	get master of bridge port, and hold it
 */
static inline struct net_device *xfe_dev_get_master(struct net_device *dev)
{
	struct net_device *master;
	rcu_read_lock();
	master = netdev_master_upper_dev_get_rcu(dev);
	if (master)
		dev_hold(master);

	rcu_read_unlock();
	return master;
}

#define XFE_DEV_EVENT_PTR(PTR) netdev_notifier_info_to_dev(PTR)

#define XFE_NF_CONN_ACCT(NM) struct nf_conn_acct *NM

#define XFE_ACCT_COUNTER(NM) ((NM)->counter)

#define xfe_hash_for_each_possible(name, obj, node, member, key) \
	hash_for_each_possible(name, obj, member, key)

#define xfe_hash_for_each(name, bkt, node, obj, member) \
	hash_for_each(name, bkt, obj, member)

#define xfe_dst_get_neighbour(dst, daddr) dst_neigh_lookup(dst, addr)

/*
 * The following are debug macros used throughout the XFE.
 *
 * The DEBUG_LEVEL enables the followings based on its value,
 * when dynamic debug option is disabled.
 *
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL 2

#if (DEBUG_LEVEL < 1)
#define DEBUG_ASSERT(s, ...)
#define DEBUG_ERROR(s, ...)
#else
#define DEBUG_ASSERT(c, s, ...) if (!(c)) { pr_emerg("ASSERT: %s:%d:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__); BUG(); }
#define DEBUG_ERROR(s, ...) pr_err("%s:%d:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if defined(CONFIG_DYNAMIC_DEBUG)
/*
 * Compile messages for dynamic enable/disable
 */
#define DEBUG_WARN(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define DEBUG_INFO(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define DEBUG_TRACE(s, ...) pr_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else

/*
 * Statically compile messages at different levels
 */
#if (DEBUG_LEVEL < 2)
#define DEBUG_WARN(s, ...)
#else
#define DEBUG_WARN(s, ...) pr_warn("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (DEBUG_LEVEL < 3)
#define DEBUG_INFO(s, ...)
#else
#define DEBUG_INFO(s, ...) pr_notice("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (DEBUG_LEVEL < 4)
#define DEBUG_TRACE(s, ...)
#else
#define DEBUG_TRACE(s, ...) pr_info("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif
#endif

/*
 * IPv4 APIs used by connection manager
 */
int xfe_ipv4_create_rule(struct xfe_connection_create *sic);
void xfe_ipv4_destroy_rule(struct xfe_connection_destroy *sid);
void xfe_ipv4_destroy_all_rules_for_dev(struct net_device *dev);
void xfe_ipv4_update_rule(struct xfe_connection_create *sic);
void xfe_ipv4_mark_rule(struct xfe_connection_mark *mark);
int xfe_ipv4_sync_rules(struct xfe_connection_sync *syncs, int count, struct sk_buff **ret);

/*
 * xfe_ipv4_addr_equal()
 *	compare ipv4 address
 *
 * return: 1, equal; 0, no equal
 */
#define xfe_ipv4_addr_equal(a, b) ((u32)(a) == (u32)(b))

/*
 * xfe_addr_equal()
 *	compare ipv4 or ipv6 address
 *
 * return: 1, equal; 0, no equal
 */
static inline int xfe_addr_equal(xfe_ip_addr_t *a,
				 xfe_ip_addr_t *b, int is_v4)
{
	return xfe_ipv4_addr_equal(a->ip, b->ip);
}

/*
 * Netlink
 */
void xfe_netlink_recv_msg(struct sk_buff *skb);
void xfe_bpf_free(void);

#include <linux/if_ether.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack_timeout.h>

#define XFE_GENL_VERSION	(1)
#define XFE_GENL_NAME	"FC"
#define XFE_GENL_MCGRP	"FC_MCGRP"
#define XFE_GENL_HDRSIZE	(0)

enum {
	XFE_A_UNSPEC,
	XFE_A_TUPLE,
	__XFE_A_MAX,
};

#define XFE_A_MAX (__XFE_A_MAX - 1)

enum {
	XFE_C_UNSPEC,
	XFE_C_OFFLOAD,
	XFE_C_OFFLOADED,
	XFE_C_DONE,
	__XFE_C_MAX,
};

#define XFE_C_MAX (__XFE_C_MAX - 1)

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
 * connection flags.
 */
#define XFE_CREATE_FLAG_NO_SEQ_CHECK BIT(0)
					/* Indicates that we should not check sequence numbers */
#define XFE_CREATE_FLAG_REMARK_PRIORITY BIT(1)
					/* Indicates that we should remark priority of skb */
#define XFE_CREATE_FLAG_REMARK_DSCP BIT(2)
					/* Indicates that we should remark DSCP of packet */

typedef union {
	__be32			ip;
} xfe_ip_addr_t;

/*
 * connection creation structure.
 */
struct xfe_connection_create {
	int protocol;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	u32 flags;
	u32 src_mtu;
	u32 dest_mtu;
	xfe_ip_addr_t src_ip;
	xfe_ip_addr_t src_ip_xlate;
	xfe_ip_addr_t dest_ip;
	xfe_ip_addr_t dest_ip_xlate;
	__be16 src_port;
	__be16 src_port_xlate;
	__be16 dest_port;
	__be16 dest_port_xlate;
	u8 src_mac[ETH_ALEN];
	u8 src_mac_xlate[ETH_ALEN];
	u8 dest_mac[ETH_ALEN];
	u8 dest_mac_xlate[ETH_ALEN];
	u8 src_td_window_scale;
	u32 src_td_max_window;
	u32 src_td_end;
	u32 src_td_max_end;
	u8 dest_td_window_scale;
	u32 dest_td_max_window;
	u32 dest_td_end;
	u32 dest_td_max_end;
	u32 mark;
#ifdef CONFIG_XFRM
	u32 original_accel;
	u32 reply_accel;
#endif
	u32 src_priority;
	u32 dest_priority;
	u32 src_dscp;
	u32 dest_dscp;
};

/*
 * connection destruction structure.
 */
struct xfe_connection_destroy {
	int protocol;
	xfe_ip_addr_t src_ip;
	xfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;
};

typedef enum xfe_sync_reason {
	XFE_SYNC_REASON_STATS,	/* Sync is to synchronize stats */
	XFE_SYNC_REASON_FLUSH,	/* Sync is to flush a entry */
	XFE_SYNC_REASON_DESTROY	/* Sync is to destroy a entry(requested by connection manager) */
} xfe_sync_reason_t;

/*
 * Structure used to sync connection stats/state back within the system.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct xfe_connection_sync {
	struct net_device *src_dev;
	struct net_device *dest_dev;
	int is_v6;			/* Is it for ipv6? */
	int protocol;			/* IP protocol number (IPPROTO_...) */
	xfe_ip_addr_t src_ip;		/* Non-NAT source address, i.e. the creator of the connection */
	xfe_ip_addr_t src_ip_xlate;	/* NATed source address */
	__be16 src_port;		/* Non-NAT source port */
	__be16 src_port_xlate;		/* NATed source port */
	xfe_ip_addr_t dest_ip;		/* Non-NAT destination address, i.e. to whom the connection was created */
	xfe_ip_addr_t dest_ip_xlate;	/* NATed destination address */
	__be16 dest_port;		/* Non-NAT destination port */
	__be16 dest_port_xlate;		/* NATed destination port */
	u32 src_td_max_window;
	u32 src_td_end;
	u32 src_td_max_end;
	u64 src_packet_count;
	u64 src_byte_count;
	u32 src_new_packet_count;
	u32 src_new_byte_count;
	u32 dest_td_max_window;
	u32 dest_td_end;
	u32 dest_td_max_end;
	u64 dest_packet_count;
	u64 dest_byte_count;
	u32 dest_new_packet_count;
	u32 dest_new_byte_count;
	u32 reason;		/* reason for stats sync message, i.e. destroy, flush, period sync */
	u64 delta_jiffies;		/* Time to be added to the current timeout to keep the connection alive */
};

/*
 * connection mark structure
 */
struct xfe_connection_mark {
	int protocol;
	xfe_ip_addr_t src_ip;
	xfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;
	u32 mark;
};

/*
 * Expose what should be a static flag in the TCP connection tracker.
 */
extern int nf_ct_tcp_no_window_check;

/*
 * This callback will be called in a timer
 * at 100 times per second to sync stats back to
 * Linux connection track.
 *
 * A RCU lock is taken to prevent this callback
 * from unregistering.
 */
typedef void (*xfe_sync_rule_callback_t)(struct xfe_connection_sync *);

/*
 * IPv4 APIs used by connection manager
 */
int xfe_ipv4_recv(struct net_device *dev, struct sk_buff *skb);
int xfe_ipv4_create_rule(struct xfe_connection_create *sic);
void xfe_ipv4_destroy_rule(struct xfe_connection_destroy *sid);
void xfe_ipv4_destroy_all_rules_for_dev(struct net_device *dev);
void xfe_ipv4_register_sync_rule_callback(xfe_sync_rule_callback_t callback);
void xfe_ipv4_update_rule(struct xfe_connection_create *sic);
void xfe_ipv4_mark_rule(struct xfe_connection_mark *mark);

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

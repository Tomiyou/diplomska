#ifndef XFE_TYPES_H
#define XFE_TYPES_H

#include <linux/if_ether.h>
#include <linux/filter.h>
#include <linux/bpf.h>
// #include <stdbool.h>

/* Map hash lookup */
#define XFE_HASH_SHIFT 12
#define XFE_HASH_SIZE (1 << XFE_HASH_SHIFT)
#define XFE_HASH_MASK (XFE_HASH_SIZE - 1)

enum xfe_nl_msg_type {
	XFE_MSG_PROG_FD
};

struct xfe_nl_msg {
	enum xfe_nl_msg_type msg_type;
	unsigned int msg_value;
};

/*
 * Bit flags for IPv4 connection matching entry.
 */
#define XFE_IPV4_CONNECTION_MATCH_FLAG_XLATE_SRC (1<<0)
					/* Perform source translation */
#define XFE_IPV4_CONNECTION_MATCH_FLAG_XLATE_DEST (1<<1)
					/* Perform destination translation */
#define XFE_IPV4_CONNECTION_MATCH_FLAG_NO_SEQ_CHECK (1<<2)
					/* Ignore TCP sequence numbers */
#define XFE_IPV4_CONNECTION_MATCH_FLAG_WRITE_FAST_ETH_HDR (1<<3)
					/* Fast Ethernet header write */
#define XFE_IPV4_CONNECTION_MATCH_FLAG_WRITE_L2_HDR (1<<4)
					/* Fast Ethernet header write */
#define XFE_IPV4_CONNECTION_MATCH_FLAG_PRIORITY_REMARK (1<<5)
					/* remark priority of SKB */
#define XFE_IPV4_CONNECTION_MATCH_FLAG_DSCP_REMARK (1<<6)
					/* remark DSCP of packet */

/* DSCP remarking */
#define XFE_IPV4_DSCP_MASK 0x3
#define XFE_IPV4_DSCP_SHIFT 2

struct xfe_flow {
	struct bpf_spin_lock lock;		/* Spinlock for every entry */

	/* Fields for matching packet to a flow */
	__u32 ifindex;				/* Network device */
	__be16 eth_proto;			/* Ethernet protocol */
	__u8 ip_proto;				/* IP protocol */
	__be32 src_ip;				/* Source IP address */
	__be32 dest_ip;				/* Destination IP address */
	__be16 src_port;			/* Source port/connection ident */
	__be16 dest_port;			/* Destination port/connection ident */

	/* Remember if we need to do NAT */
	bool is_bridged;

	/* Fields for translating a packet */
	__u32 xmit_ifindex;			/* Network device */
	unsigned char xlate_src_mac[ETH_ALEN];	/* Source MAC */
	unsigned char xlate_dst_mac[ETH_ALEN];	/* Destination MAC */
	__be32 xlate_src_ip;			/* Source IP address */
	__be32 xlate_dest_ip;			/* Destination IP address */
	__be16 xlate_src_port;			/* Source port/connection ident */
	__be16 xlate_dest_port;			/* Destination port/connection ident */

	/* Stats */
	__u32 packet_count;
	__u32 packet_count_tick;
	__u64 byte_count;
	__u64 byte_count_tick;

	/* QoS information */
	__u8 tos;
	__u32 flags;
	__u32 mark;
	__u32 priority;
	__u32 dscp;
};

#define XFE_CREATE_FLAG_NO_SEQ_CHECK (1<<0)
					/* Indicates that we should not check sequence numbers */
#define XFE_CREATE_FLAG_REMARK_PRIORITY (1<<1)
					/* Indicates that we should remark priority of skb */
#define XFE_CREATE_FLAG_REMARK_DSCP (1<<2)
					/* Indicates that we should remark DSCP of packet */

typedef union {
	__be32			ip;
} xfe_ip_addr_t;

/*
 * Connection creation structure.
 */
struct xfe_connection_create {
	/* Interfaces */
	__u32 src_ifindex;
	__u32 src_mtu;
	__u32 dest_ifindex;
	__u32 dest_mtu;

	/* Packet match info */
	__u16 eth_proto;
	__u8 ip_proto;
	xfe_ip_addr_t src_ip;
	xfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;

	/* Packet translate info */
	__u8 xlate_src_mac[ETH_ALEN];
	__u8 xlate_dest_mac[ETH_ALEN];
	xfe_ip_addr_t xlate_src_ip;
	xfe_ip_addr_t xlate_dest_ip;
	__be16 xlate_src_port;
	__be16 xlate_dest_port;

	/* QoS */
	__u32 flags;
	__u32 mark;
	__u32 xlate_priority;
	__u32 xlate_dscp;
};

/*
 * Connection destruction structure.
 */
struct xfe_connection_destroy {
	__u8 ip_proto;
	xfe_ip_addr_t src_ip;
	xfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__u32 packets;
};

/*
 * Structure used to sync connection stats/state back within the system.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct xfe_connection_sync {
	__u8 ip_proto;
	xfe_ip_addr_t src_ip;
	xfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__u32 ifindex;
	__u32 packets;
	__u64 bytes;
};

/*
 * Connection mark structure
 */
struct xfe_connection_mark {
	int protocol;
	xfe_ip_addr_t src_ip;
	xfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;
	__u32 mark;
};

enum xfe_kmod_action {
	XFE_KMOD_INSERT,
	XFE_KMOD_UPDATE,
	XFE_KMOD_DESTROY,
	XFE_KMOD_SYNC,
	XFE_KMOD_MARK,
	XFE_KMOD_FLUSH
};

/* 
 * Message structure for passing between kernel module and XDP
 */
struct xfe_kmod_message {
	enum xfe_kmod_action action;
	union {
		struct xfe_connection_create create;
		struct xfe_connection_destroy destroy;
		struct xfe_connection_mark mark;
		__u32 ifindex;
	};
};
struct xfe_kmod_message_sync {
	enum xfe_kmod_action action;
	struct xfe_connection_sync sync[1024];
	__u16 connection_count;
};

#endif /* XFE_TYPES_H */

/* SPDX-License-Identifier: GPL-2.0 */
#define KBUILD_MODNAME "foo"
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/types.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

/* BPF stuff */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../headers/xfe_types.h"

/* Debug logging */
#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
	static const char ____fmt[] = fmt;              \
	bpf_trace_printk(____fmt, sizeof(____fmt),      \
			 ##__VA_ARGS__);                \
})

/*
 * The following are debug macros used throughout the XFE.
 *
 * The DEBUG_LEVEL enables the followings based on its value,
 * when dynamic debug option is disabled.
 *
 * 0 = OFF
 * 1 = ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL 3

#if (DEBUG_LEVEL < 1)
	#define DEBUG_ERROR(...)
#else
	#define DEBUG_ERROR(...) bpf_printk("ERROR: " __VA_ARGS__)
#endif

#if (DEBUG_LEVEL < 2)
	#define DEBUG_WARN(...)
#else
	#define DEBUG_WARN(...) bpf_printk(__VA_ARGS__)
#endif

#if (DEBUG_LEVEL < 3)
	#define DEBUG_INFO(...)
#else
	#define DEBUG_INFO(...) bpf_printk(__VA_ARGS__)
#endif

#if (DEBUG_LEVEL < 4)
	#define DEBUG_TRACE(...)
#else
	#define DEBUG_TRACE(...) bpf_printk(__VA_ARGS__)
#endif

/* memcpy() and memset() for eBPF */
#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

struct xfe_flow_key {
	__u8 ip_proto;
	__be32 src_ip;
	__be32 dest_ip;
	__be16 src_port;
	__be16 dest_port;
};

/* This map stores all the accelerated XFE flows
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct xfe_flow_key);
	__type(value, struct xfe_flow);
	__uint(max_entries, XFE_HASH_SIZE);
} xdp_povezave SEC(".maps");

struct xfe_instance {
	/* Global instance lock */
	// struct bpf_spin_lock lock;

	/* Stats */
	__u32 connection_create_requests;	/* Number of connection create requests */
	__u32 connection_create_collisions;	/* Number of connection create requests that collided with existing hash table entries */
	__u32 connection_destroy_requests;	/* Number of connection destroy requests */
	__u32 connection_destroy_misses;	/* Number of connection destroy requests that missed our hash table */
	__u32 connection_match_hash_hits;	/* Number of connection match hash hits */
	__u32 connection_match_hash_reorders;	/* Number of connection match hash reorders */
	__u32 connection_flushes;		/* Number of connection flushes */
	__u32 packets_forwarded;		/* Number of packets forwarded */
	__u32 packets_not_forwarded;		/* Number of packets not forwarded */
	__u32 xfe_exceptions;			/* Number of xfe exceptions that occurred */
};

/* This is just a map with a global lock for concurrency
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct xfe_instance);
	__uint(max_entries, 1);
} globalne_spremenljivke SEC(".maps");

/* Map for storing large structs
 * This is how we get around the 512 byte stack limit
 * For some reason, this does not work with BTF, so we use "normal" BPF
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xfe_flow));
    __uint(max_entries, 1);
} ekstra_pomnilnik SEC(".maps");

static const __u32 always_zero = 0;

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

/* Parse ethernet header */
static __always_inline struct ethhdr *parse_ethhdr(void *data_start,
						   void *data_end)
{
	struct ethhdr *eth_hdr = data_start;
	int hdr_size = sizeof(*eth_hdr);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return eth_hdr; /* network-byte-order */
}

/* Parse IPv4 header */
static __always_inline struct iphdr *parse_iphdr(void *data_start,
						 void *data_end)
{
	struct iphdr *ip_hdr = data_start;
	int hdr_size = sizeof(*ip_hdr);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return ip_hdr; /* network-byte-order */
}

/* Parse TCP header */
static __always_inline struct tcphdr *parse_tcphdr(void *data_start,
						   void *data_end)
{
	struct tcphdr *tcp_header = data_start;
	int hdr_size = sizeof(*tcp_header);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return tcp_header; /* network-byte-order */
}

/* Parse UDP header */
static __always_inline struct udphdr *parse_udphdr(void *data_start,
						   void *data_end)
{
	struct udphdr *udp_header = data_start;
	int hdr_size = sizeof(*udp_header);

	/* Byte-count bounds check; check if data_start + size of header
	 * is after data_end. */
	if (data_start + hdr_size > data_end)
		return NULL;

	return udp_header; /* network-byte-order */
}

/* IPv4 */
__attribute__((__always_inline__))
static inline __u16 csum_fold_helper1(__u64 csum) {
	int i;
	#pragma unroll
	for (i = 0; i < 4; i ++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void *data_start, int data_size,  __u64 *csum) {
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper1(*csum);
}

/* L4 */
static __always_inline uint32_t csum_add(uint32_t addend, uint32_t csum) 
{
	uint32_t res = csum;
	res += addend;
	return (res + (res < addend));
}

static __always_inline uint32_t csum_sub(uint32_t addend, uint32_t csum) 
{
	return csum_add(csum, ~addend);
}

static __always_inline uint16_t csum_fold_helper2(uint32_t csum) 
{
	uint32_t r = csum << 16 | csum >> 16;
	csum = ~csum;
	csum -= r;
	return (uint16_t)(csum >> 16);
}

static __always_inline uint16_t csum_diff4(uint32_t from, uint32_t to, uint16_t csum) 
{
	uint32_t tmp = csum_sub(from, ~((uint32_t)csum));
	return csum_fold_helper2(csum_add(to, tmp));
}

SEC("posredovalnik")
int posredovalnik_fn(struct xdp_md *ctx)
{
	void *data_start = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *frame_pointer = data_start;

	/* Packet headers */
	struct ethhdr *eth_hdr;
	struct iphdr *ip_hdr;
	struct xfe_flow *flow;
	struct xfe_flow_key flow_key = {0};

	/* Default action */
	long action = XDP_PASS;

	/* Parse ethernet header */
	eth_hdr = parse_ethhdr(frame_pointer, data_end);
	if (eth_hdr == NULL) {
		goto out;
	}
	/* Move frame pointer */
	frame_pointer += sizeof(*eth_hdr);

	/* Only allow IPv4 packets through */
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IP)) {
		goto out;
	}

	/* Parse IPv4 header */
	ip_hdr = parse_iphdr(frame_pointer, data_end);
	if (ip_hdr == NULL) {
		goto out;
	}
	/* Move frame pointer */
	frame_pointer += sizeof(*ip_hdr);

	DEBUG_TRACE("Processing IPv4 packet with ID: %u", bpf_ntohs(ip_hdr->id));

	if (ip_hdr->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp_hdr;

		/* Parse TCP header */
		tcp_hdr = parse_tcphdr(frame_pointer, data_end);
		if (tcp_hdr == NULL) {
			goto out;
		}
		/* Move frame pointer */
		frame_pointer += sizeof(*tcp_hdr);

		/* Do flow lookup */
		flow_key.ip_proto = ip_hdr->protocol;
		flow_key.src_ip = ip_hdr->saddr;
		flow_key.dest_ip = ip_hdr->daddr;
		flow_key.src_port = tcp_hdr->source;
		flow_key.dest_port = tcp_hdr->dest;
		flow = bpf_map_lookup_elem(&xdp_povezave, &flow_key);
		if (!flow) {
			goto out;
		}

		DEBUG_TRACE("TCP flow lookup SUCCEEDEDs!");
		DEBUG_TRACE("L2 %x:%x:%x", flow->xlate_src_mac[0], flow->xlate_src_mac[1], flow->xlate_src_mac[2]);
		DEBUG_TRACE("   %x:%x:%x", flow->xlate_src_mac[3], flow->xlate_src_mac[4], flow->xlate_src_mac[5]);
		DEBUG_TRACE("L2 %x:%x:%x", flow->xlate_dst_mac[0], flow->xlate_dst_mac[1], flow->xlate_dst_mac[2]);
		DEBUG_TRACE("   %x:%x:%x", flow->xlate_dst_mac[3], flow->xlate_dst_mac[4], flow->xlate_dst_mac[5]);
		DEBUG_TRACE("L3 %pI4 -> %pI4", &ip_hdr->saddr, &ip_hdr->daddr);
		DEBUG_TRACE("L3 %pI4 -> %pI4", &flow->xlate_src_ip, &flow->xlate_dest_ip);
		DEBUG_TRACE("L4 %u -> %u\n", bpf_ntohs(flow->xlate_src_port), bpf_ntohs(flow->xlate_dest_port));

		/* If we have any TCP flag, send packet through slowpath */
		if (tcp_hdr->syn || tcp_hdr->rst || tcp_hdr->fin) {
			goto out;
		}

		/* Forward the packet */
		memcpy(eth_hdr->h_source, flow->xlate_src_mac, ETH_ALEN);
		memcpy(eth_hdr->h_dest, flow->xlate_dst_mac, ETH_ALEN);

		/* L3 header */
		tcp_hdr->check = csum_diff4(ip_hdr->daddr, flow->xlate_dest_ip, tcp_hdr->check);
		ip_hdr->daddr = flow->xlate_dest_ip;
		tcp_hdr->check = csum_diff4(ip_hdr->saddr, flow->xlate_src_ip, tcp_hdr->check);
		ip_hdr->saddr = flow->xlate_src_ip;
		ip_hdr->ttl = ip_hdr->ttl - 1;

		/* L4 header */
		tcp_hdr->check = csum_diff4(tcp_hdr->source, flow->xlate_src_port, tcp_hdr->check);
		tcp_hdr->source = flow->xlate_src_port;
		tcp_hdr->check = csum_diff4(tcp_hdr->dest, flow->xlate_dest_port, tcp_hdr->check);
		tcp_hdr->dest = flow->xlate_dest_port;
	} else if (ip_hdr->protocol == IPPROTO_UDP) {
		struct udphdr *udp_hdr;

		/* Parse UDP header */
		udp_hdr = parse_udphdr(frame_pointer, data_end);
		if (udp_hdr == NULL) {
			goto out;
		}
		/* Move frame pointer */
		frame_pointer += sizeof(*udp_hdr);

		/* Do flow lookup */
		flow_key.ip_proto = ip_hdr->protocol;
		flow_key.src_ip = ip_hdr->saddr;
		flow_key.dest_ip = ip_hdr->daddr;
		flow_key.src_port = udp_hdr->source;
		flow_key.dest_port = udp_hdr->dest;
		flow = bpf_map_lookup_elem(&xdp_povezave, &flow_key);
		if (!flow) {
			goto out;
		}

		DEBUG_TRACE("UDP flow lookup SUCCEEDED!");
		DEBUG_TRACE("Header values, IP: %x -> %x (DST PORT: %x) ",
			bpf_ntohl(ip_hdr->saddr), bpf_ntohl(ip_hdr->daddr),
			udp_hdr->dest);
		DEBUG_TRACE("%u, %x, %x",
			ctx->ingress_ifindex,
			bpf_ntohs(eth_hdr->h_proto),
			ip_hdr->protocol);

		/* Forward the packet */
		memcpy(eth_hdr->h_source, flow->xlate_src_mac, ETH_ALEN);
		memcpy(eth_hdr->h_dest, flow->xlate_dst_mac, ETH_ALEN);

		/* L3 header */
		udp_hdr->check = csum_diff4(ip_hdr->daddr, flow->xlate_dest_ip, udp_hdr->check);
		ip_hdr->daddr = flow->xlate_dest_ip;
		udp_hdr->check = csum_diff4(ip_hdr->saddr, flow->xlate_src_ip, udp_hdr->check);
		ip_hdr->saddr = flow->xlate_src_ip;
		ip_hdr->ttl = ip_hdr->ttl - 1;

		/* L4 header */
		udp_hdr->check = csum_diff4(udp_hdr->source, flow->xlate_src_port, udp_hdr->check);
		udp_hdr->source = flow->xlate_src_port;
		udp_hdr->check = csum_diff4(udp_hdr->dest, flow->xlate_dest_port, udp_hdr->check);
		udp_hdr->dest = flow->xlate_dest_port;
	} else {
		goto out;
	}

	/* IPv4 checksum */
	ip_hdr->check = 0;
	__u64 ip_csum = 0;
	ipv4_csum(ip_hdr, sizeof(*ip_hdr), &ip_csum);
	ip_hdr->check = ip_csum;

	/* Increase packet counters */
	// bpf_spin_lock(&flow->lock);
	flow->packet_count += 1;
	flow->packet_count_tick += 1;
	flow->byte_count += (ctx->data_end - ctx->data);
	flow->byte_count_tick += (ctx->data_end - ctx->data);
	// bpf_spin_unlock(&flow->lock);

	/* Redirect the packet to the correct output interface */
	action = bpf_redirect(flow->xmit_ifindex, 0);
	if (action == XDP_ABORTED) {
		DEBUG_ERROR("Redirect did not go through %d %ld\n", flow->xmit_ifindex, action);
	}

out:
	return action;
}

SEC("sinhronizator")
int sinhronizator_fn(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct xfe_instance *xfe;
	struct xfe_flow *flow;
	struct xfe_flow_key flow_key = {0};
	long err = 0;

	/* Instructions on what to do */
	struct xfe_kmod_message *msg;
	struct xfe_kmod_message_sync *sync_msg;
	unsigned int msg_size = sizeof(*msg);
	unsigned int sync_size = sizeof(*sync_msg);

	/* Byte-count bounds check; check if msg + size of header
	 * is after data_end. */
	if (data + msg_size > data_end) {
		DEBUG_ERROR("sinhronizator_fn: data bound check failed!");
		return -1;
	}

	msg = (struct xfe_kmod_message *) data;

	if (msg->action == XFE_KMOD_INSERT) {
		struct xfe_connection_create *create = &msg->create;

		memset(&flow, 0, sizeof(flow));

		DEBUG_INFO("Inserting rule");
		/* Flow hash is always 0 here so use it to lookup xfe_flow struct */
		flow = bpf_map_lookup_elem(&ekstra_pomnilnik, &always_zero);
		if (flow == NULL) {
			DEBUG_ERROR("Error getting stack bypass struct");
			return -1;
		}

		/* Flow match info */
		flow->ifindex = create->src_ifindex;
		flow->eth_proto = create->eth_proto;
		flow->ip_proto = create->ip_proto;
		flow->src_ip = create->src_ip.ip;
		flow->dest_ip = create->dest_ip.ip;
		flow->src_port = create->src_port;
		flow->dest_port = create->dest_port;

		flow->is_bridged = false;

		/* Flow xlate info */
		flow->xmit_ifindex = create->dest_ifindex;
		memcpy(flow->xlate_src_mac, create->xlate_src_mac, ETH_ALEN);
		memcpy(flow->xlate_dst_mac, create->xlate_dest_mac, ETH_ALEN);
		flow->xlate_src_ip = create->xlate_src_ip.ip;
		flow->xlate_dest_ip = create->xlate_dest_ip.ip;
		flow->xlate_src_port = create->xlate_src_port;
		flow->xlate_dest_port = create->xlate_dest_port;
		DEBUG_INFO("B2 %x:%x:%x", flow->xlate_src_mac[0], flow->xlate_src_mac[1], flow->xlate_src_mac[2]);
		DEBUG_INFO("   %x:%x:%x", flow->xlate_src_mac[3], flow->xlate_src_mac[4], flow->xlate_src_mac[5]);
		DEBUG_INFO("B2 %x:%x:%x", flow->xlate_dst_mac[0], flow->xlate_dst_mac[1], flow->xlate_dst_mac[2]);
		DEBUG_INFO("   %x:%x:%x", flow->xlate_dst_mac[3], flow->xlate_dst_mac[4], flow->xlate_dst_mac[5]);

		/* Stats */
		flow->packet_count = 0;
		flow->byte_count = 0;

		/* Flags */
		flow->flags = 0;
		if (create->flags & XFE_CREATE_FLAG_REMARK_PRIORITY) {
			flow->priority = create->xlate_priority;
			flow->flags |= XFE_IPV4_CONNECTION_MATCH_FLAG_PRIORITY_REMARK;
		}
		if (create->flags & XFE_CREATE_FLAG_REMARK_DSCP) {
			flow->dscp = create->xlate_dscp << XFE_IPV4_DSCP_SHIFT;
			flow->flags |= XFE_IPV4_CONNECTION_MATCH_FLAG_DSCP_REMARK;
		}
		if (create->dest_ip.ip != create->xlate_dest_ip.ip ||
			create->dest_port != create->xlate_dest_port) {
			flow->flags |= XFE_IPV4_CONNECTION_MATCH_FLAG_XLATE_DEST;
		}
		if (create->src_ip.ip != create->xlate_src_ip.ip ||
			create->src_port != create->xlate_src_port) {
			flow->flags |= XFE_IPV4_CONNECTION_MATCH_FLAG_XLATE_SRC;
		}

		/* Insert flow into hash table */
		flow_key.ip_proto = create->ip_proto;
		flow_key.src_ip = create->src_ip.ip;
		flow_key.dest_ip = create->dest_ip.ip;
		flow_key.src_port = create->src_port;
		flow_key.dest_port = create->dest_port;
		err = bpf_map_update_elem(&xdp_povezave, &flow_key, flow, BPF_NOEXIST);
		if (err) {
			DEBUG_WARN("bpf_map_update_elem failed, flow already exists");
		} else {
			DEBUG_INFO("sinhronizator_fn: create hash %d", err);
		}

		/* Update stats */
		xfe = bpf_map_lookup_elem(&globalne_spremenljivke, &always_zero);
		if (!xfe) {
			return err;
		}

		// bpf_spin_lock(&xfe->lock);
		xfe->connection_create_requests++;
		if (err) {
			xfe->connection_create_collisions++;
		}
		// bpf_spin_unlock(&xfe->lock);
		return err;
	} else if (msg->action == XFE_KMOD_DESTROY) {
		struct xfe_connection_destroy *destroy = &msg->destroy;

		/* Remove flow from hash table */
		flow_key.ip_proto = destroy->ip_proto;
		flow_key.src_ip = destroy->src_ip.ip;
		flow_key.dest_ip = destroy->dest_ip.ip;
		flow_key.src_port = destroy->src_port;
		flow_key.dest_port = destroy->dest_port;
		err = bpf_map_delete_elem(&xdp_povezave, &flow_key);
		DEBUG_INFO("sinhronizator_fn: destroy hash %d", err);

		/* Update stats */
		xfe = bpf_map_lookup_elem(&globalne_spremenljivke, &always_zero);
		if (!xfe) {
			return err;
		}

		// bpf_spin_lock(&xfe->lock);
		xfe->connection_destroy_requests++;
		if (err) {
			xfe->connection_destroy_misses++;
		}
		// bpf_spin_unlock(&xfe->lock);
		return err;
	} else if (msg->action == XFE_KMOD_UPDATE) {
	} else if (msg->action == XFE_KMOD_SYNC) {
		struct xfe_connection_sync *sync;
		int i;

		if (data + sync_size > data_end) {
			DEBUG_ERROR("sinhronizator_fn: data bound check failed!");
			return -1;
		}

		sync_msg = (struct xfe_kmod_message_sync *) data;

		DEBUG_TRACE("Connection SYNC called: %u\n", sync_msg->connection_count);

		/* Get counters for each flow entry */
		for (i = 0; i < 1024; i++) {
			if (i >= sync_msg->connection_count) {
				break;
			}

			sync = &sync_msg->sync[i];
			flow_key.ip_proto = sync->ip_proto;
			flow_key.src_ip = sync->src_ip.ip;
			flow_key.dest_ip = sync->dest_ip.ip;
			flow_key.src_port = sync->src_port;
			flow_key.dest_port = sync->dest_port;
			flow = bpf_map_lookup_elem(&xdp_povezave, &flow_key);
			if (!flow) {
				continue;
			}

			DEBUG_TRACE("Syncing connection: %u %u %u\n", bpf_ntohs(sync->src_port), bpf_ntohs(sync->dest_port), flow->packet_count_tick);

			/* Copy and reset counters */
			// bpf_spin_lock(&flow->lock);
			sync->packets = flow->packet_count_tick;
			sync->bytes = flow->byte_count_tick;
			flow->packet_count_tick = 0;
			flow->byte_count_tick = 0;
			// bpf_spin_unlock(&flow->lock);
		}

	} else {
		DEBUG_ERROR("sinhronizator_fn: unknown action received %u", msg->action);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
	// (Note: type __u32 is NOT the real-type)
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index
};
*/

/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

/* BPF stuff */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xfe_types.h"

/* Lesson: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
struct bpf_map_def SEC("maps") xfe_flows = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct xfe_flow),
	.max_entries = 254, /* TODO: change this to something bigger */
};

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

// /* Map hash lookup */
// #define HASH_SHIFT 12
// #define HASH_SIZE (1 << HASH_SHIFT)
// #define HASH_MASK (HASH_SIZE - 1)

// static __always_inline __u32 get_flow_hash(
// 	__u32 if_index,
// 	__be16 eth_proto,
// 	__u8   ip_proto,
// 	__be32 src_ip,
// 	__be32 dest_ip,
// 	__be16 src_port,
// 	__be16 dest_port
// )
// {
// 	__u32 hash = if_index ^ bpf_ntohl(src_ip ^ dest_ip) ^ bpf_ntohs(eth_proto) ^ ip_proto ^ bpf_ntohs(src_port ^ dest_port);
// 	return ((hash >> HASH_SHIFT) ^ hash) & HASH_MASK;
// }

static __always_inline struct xfe_flow *lookup_flow(
	__u32 if_index,
	unsigned char dst_mac[ETH_ALEN],
	__be16 eth_proto,
	__u8   ip_proto,
	__be32 src_ip,
	__be32 dest_ip,
	__be16 src_port,
	__be16 dest_port
)
{
	struct xfe_flow *flow;
	// __u32 hash = get_flow_hash(0, eth_proto,
	// 			   ip_proto, src_ip, dest_ip,
	// 			   src_port, dest_port);
	__u32 hash = 27;

	flow = bpf_map_lookup_elem(&xfe_flows, &hash);
	if (flow == NULL)
	{
		bpf_printk("bpf_map_lookup_elem returned NULL");
		return NULL;
	}
	bpf_printk("Flow values, IP: %x -> %x (DST PORT: %x) ",
		   bpf_ntohl(flow->match_src_ip), bpf_ntohl(flow->match_dest_ip),
		   bpf_ntohs(flow->match_dest_port));
	bpf_printk("%u, %x, %x",
		   flow->match_if_index,
		   bpf_ntohs(flow->match_eth_proto),
		   flow->match_ip_proto);

	if (
		/* flow->match_if_index == if_index && */
		/* __builtin_memcmp(flow->match_dst_mac, dst_mac, 6), */
		flow->match_eth_proto == eth_proto &&
		flow->match_ip_proto == ip_proto &&
		flow->match_src_ip == src_ip &&
		flow->match_dest_ip == dest_ip &&
		flow->match_src_port == src_port &&
		flow->match_dest_port == dest_port
	)
	{
		return flow;
	}

	bpf_printk("Hash correct, but comparison wrong");
	return NULL;
}

SEC("xfe_ingress")
int xfe_ingress_fn(struct xdp_md *ctx)
{
	void *data_start = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *frame_pointer = data_start;

	/* Packet headers */
	struct ethhdr *eth_hdr;
	struct iphdr *ip_hdr;
	struct udphdr *udp_hdr;
	struct xfe_flow *flow;

	/* Default action */
	__u32 action = XDP_PASS;

	/* Parse ethernet header */
	eth_hdr = parse_ethhdr(frame_pointer, data_end);
	if (eth_hdr == NULL)
		goto out;
	/* Move frame pointer */
	frame_pointer += sizeof(*eth_hdr);

	/* Only allow IPv4 packets through */
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IP))
		goto out;

	/* Parse IPv4 header */
	ip_hdr = parse_iphdr(frame_pointer, data_end);
	if (ip_hdr == NULL)
		goto out;
	/* Move frame pointer */
	frame_pointer += sizeof(*ip_hdr);

	/* Only allow UDP packets through */
	if (ip_hdr->protocol != IPPROTO_UDP)
		goto out;

	/* Parse UDP header */
	udp_hdr = parse_udphdr(frame_pointer, data_end);
	if (udp_hdr == NULL)
		goto out;
	/* Move frame pointer */
	frame_pointer += sizeof(*udp_hdr);
	bpf_printk("");

	/* Ready to process UDP packet */
	flow = lookup_flow(ctx->ingress_ifindex, eth_hdr->h_dest, eth_hdr->h_proto,
			   ip_hdr->protocol, ip_hdr->saddr, ip_hdr->daddr,
			   /* udp_hdr->source */0, udp_hdr->dest);
	if (!flow)
	{
		bpf_printk("Flow lookup failed.");
	}
	else
	{
		bpf_printk("Flow lookup SUCCEEDED!");
	}

	bpf_printk("Headerx values, IP: %x -> %x (DST PORT: %x) ",
		   bpf_ntohl(ip_hdr->saddr), bpf_ntohl(ip_hdr->daddr),
		   bpf_ntohs(udp_hdr->dest));
	bpf_printk("%u, %x, %x",
		   ctx->ingress_ifindex,
		   bpf_ntohs(eth_hdr->h_proto),
		   ip_hdr->protocol);
out:
	return action;
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

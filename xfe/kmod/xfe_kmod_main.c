#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/dsfield.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/xt_dscp.h>
#include <net/genetlink.h>
#include <linux/spinlock.h>
#include <linux/if_bridge.h>
#include <linux/hashtable.h>

#include "xfe_types.h"
#include "xfe_kmod.h"

#define NETLINK_TEST 17

static struct sock *nl_sock = NULL;

typedef enum xfe_exception {
	XFE_EXCEPTION_PACKET_BROADCAST,
	XFE_EXCEPTION_PACKET_MULTICAST,
	XFE_EXCEPTION_NO_IIF,
	XFE_EXCEPTION_NO_CT,
	XFE_EXCEPTION_CT_NO_TRACK,
	XFE_EXCEPTION_CT_NO_CONFIRM,
	XFE_EXCEPTION_CT_IS_ALG,
	XFE_EXCEPTION_IS_IPV4_MCAST,
	XFE_EXCEPTION_IS_IPV6_MCAST,
	XFE_EXCEPTION_TCP_NOT_ASSURED,
	XFE_EXCEPTION_TCP_NOT_ESTABLISHED,
	XFE_EXCEPTION_UNKNOW_PROTOCOL,
	XFE_EXCEPTION_NO_SRC_DEV,
	XFE_EXCEPTION_NO_SRC_XLATE_DEV,
	XFE_EXCEPTION_NO_DEST_DEV,
	XFE_EXCEPTION_NO_DEST_XLATE_DEV,
	XFE_EXCEPTION_NO_BRIDGE,
	XFE_EXCEPTION_LOCAL_OUT,
	XFE_EXCEPTION_WAIT_FOR_ACCELERATION,
	XFE_EXCEPTION_UPDATE_PROTOCOL_FAIL,
	XFE_EXCEPTION_CT_DESTROY_MISS,
	XFE_EXCEPTION_MAX
} xfe_exception_t;

static char *xfe_exception_events_string[XFE_EXCEPTION_MAX] = {
	"PACKET_BROADCAST",
	"PACKET_MULTICAST",
	"NO_IIF",
	"NO_CT",
	"CT_NO_TRACK",
	"CT_NO_CONFIRM",
	"CT_IS_ALG",
	"IS_IPV4_MCAST",
	"IS_IPV6_MCAST",
	"TCP_NOT_ASSURED",
	"TCP_NOT_ESTABLISHED",
	"UNKNOW_PROTOCOL",
	"NO_SRC_DEV",
	"NO_SRC_XLATE_DEV",
	"NO_DEST_DEV",
	"NO_DEST_XLATE_DEV",
	"NO_BRIDGE",
	"LOCAL_OUT",
	"WAIT_FOR_ACCELERATION",
	"UPDATE_PROTOCOL_FAIL",
	"CT_DESTROY_MISS",
};

/*
 * Per-module structure.
 */
struct xfe {
	spinlock_t lock;		/* Lock for SMP correctness */

	/*
	 * Control state.
	 */
	struct kobject *sys_xfe;	/* sysfs linkage */

	/*
	 * Callback notifiers.
	 */
	struct notifier_block dev_notifier;	/* Device notifier */
	struct notifier_block inet_notifier;	/* IPv4 notifier */
	u32 exceptions[XFE_EXCEPTION_MAX];
};

static struct xfe __sc;

static atomic_t offload_msgs = ATOMIC_INIT(0);
static atomic_t offload_no_match_msgs = ATOMIC_INIT(0);
static atomic_t offloaded_msgs = ATOMIC_INIT(0);
static atomic_t done_msgs = ATOMIC_INIT(0);

static atomic_t offloaded_fail_msgs = ATOMIC_INIT(0);
static atomic_t done_fail_msgs = ATOMIC_INIT(0);

/*
 * Accelerate incoming packets destined for bridge device
 * 	If a incoming packet is ultimatly destined for
 * 	a bridge device we will first see the packet coming
 * 	from the phyiscal device, we can skip straight to
 * 	processing the packet like it came from the bridge
 * 	for some more performance gains
 *
 * 	This only works when the hook is above the bridge. We
 * 	only implement ingress for now, because for egress we
 * 	want to have the bridge devices qdiscs be used.
 */
static bool skip_to_bridge_ingress;

/*
 * xfe_incr_exceptions()
 *	increase an exception counter.
 */
static inline void xfe_incr_exceptions(xfe_exception_t except)
{
	struct xfe *sc = &__sc;

	spin_lock_bh(&sc->lock);
	sc->exceptions[except]++;
	spin_unlock_bh(&sc->lock);
}

/*
 * xfe_find_dev_and_mac_addr()
 *	Find the device and MAC address for a given IPv4 address.
 *
 * Returns true if we find the device and MAC address, otherwise false.
 *
 * We look up the rtable entry for the address and, from its neighbour
 * structure, obtain the hardware address.  This means this function also
 * works if the neighbours are routers too.
 */
static bool xfe_find_dev_and_mac_addr(xfe_ip_addr_t *addr, struct net_device **dev, u8 *mac_addr, bool is_v4)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct dst_entry *dst;
	struct net_device *mac_dev;

	/*
	 * Look up the rtable entry for the IP address then get the hardware
	 * address from its neighbour structure.  This means this works when the
	 * neighbours are routers too.
	 */
	rt = ip_route_output(&init_net, addr->ip, 0, 0, 0);
	if (unlikely(IS_ERR(rt))) {
		goto ret_fail;
	}

	dst = (struct dst_entry *)rt;

	rcu_read_lock();
	neigh = xfe_dst_get_neighbour(dst, addr);
	if (unlikely(!neigh)) {
		rcu_read_unlock();
		dst_release(dst);
		goto ret_fail;
	}

	if (unlikely(!(neigh->nud_state & NUD_VALID))) {
		rcu_read_unlock();
		neigh_release(neigh);
		dst_release(dst);
		goto ret_fail;
	}

	mac_dev = neigh->dev;
	if (!mac_dev) {
		rcu_read_unlock();
		neigh_release(neigh);
		dst_release(dst);
		goto ret_fail;
	}

	memcpy(mac_addr, neigh->ha, (size_t)mac_dev->addr_len);

	dev_hold(mac_dev);
	*dev = mac_dev;
	rcu_read_unlock();
	neigh_release(neigh);
	dst_release(dst);

	return true;

ret_fail:
	DEBUG_TRACE("failed to find MAC address for IP: %pI4\n", addr);

	return false;
}

static DEFINE_SPINLOCK(xfe_connections_lock);

struct xfe_connection {
	struct hlist_node hl;
	struct xfe_connection_create *sic;
	struct nf_conn *ct;
	int hits;
	int offload_permit;
	int offloaded;
	bool is_v4;
	unsigned char smac[ETH_ALEN];
	unsigned char dmac[ETH_ALEN];
};

static int xfe_connections_size;

#define FC_CONN_HASH_ORDER 13
static DEFINE_HASHTABLE(fc_conn_ht, FC_CONN_HASH_ORDER);

static u32 fc_conn_hash(xfe_ip_addr_t *saddr, xfe_ip_addr_t *daddr,
			unsigned short sport, unsigned short dport, bool is_v4)
{
	u32 idx, cnt = ((sizeof(saddr->ip))/sizeof(u32));
	u32 hash = 0;

	for (idx = 0; idx < cnt; idx++) {
		hash ^= ((u32 *)saddr)[idx] ^ ((u32 *)daddr)[idx];
	}

	return hash ^ (sport | (dport << 16));
}

/*
 * xfe_update_protocol()
 * 	Update xfe_ipv4_create struct with new protocol information before we offload
 */
static int xfe_update_protocol(struct xfe_connection_create *p_sic, struct nf_conn *ct)
{
	switch (p_sic->ip_proto) {
	case IPPROTO_TCP:
		/* We don't care about this right now */
		// p_sic->src_td_window_scale = ct->proto.tcp.seen[0].td_scale;
		// p_sic->src_td_max_window = ct->proto.tcp.seen[0].td_maxwin;
		// p_sic->src_td_end = ct->proto.tcp.seen[0].td_end;
		// p_sic->src_td_max_end = ct->proto.tcp.seen[0].td_maxend;
		// p_sic->dest_td_window_scale = ct->proto.tcp.seen[1].td_scale;
		// p_sic->dest_td_max_window = ct->proto.tcp.seen[1].td_maxwin;
		// p_sic->dest_td_end = ct->proto.tcp.seen[1].td_end;
		// p_sic->dest_td_max_end = ct->proto.tcp.seen[1].td_maxend;

		/* TODO */
		// if (nf_ct_tcp_no_window_check
		//     || (ct->proto.tcp.seen[0].flags & IP_CT_TCP_FLAG_BE_LIBERAL)
		//     || (ct->proto.tcp.seen[1].flags & IP_CT_TCP_FLAG_BE_LIBERAL)) {
		// 	p_sic->flags |= XFE_CREATE_FLAG_NO_SEQ_CHECK;
		// }

		/*
		 * If the connection is shutting down do not manage it.
		 * state can not be SYN_SENT, SYN_RECV because connection is assured
		 * Not managed states: FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE.
		 */
		spin_lock(&ct->lock);
		if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
			spin_unlock(&ct->lock);
			xfe_incr_exceptions(XFE_EXCEPTION_TCP_NOT_ESTABLISHED);
			DEBUG_TRACE("connection in termination state: %#x, s: %pI4:%u, d: %pI4:%u\n",
				    ct->proto.tcp.state, &p_sic->src_ip, ntohs(p_sic->src_port),
				    &p_sic->dest_ip, ntohs(p_sic->dest_port));
			return 0;
		}
		spin_unlock(&ct->lock);
		break;

	case IPPROTO_UDP:
		break;

	default:
		xfe_incr_exceptions(XFE_EXCEPTION_UNKNOW_PROTOCOL);
		DEBUG_TRACE("unhandled protocol %d\n", p_sic->ip_proto);
		return 0;
	}

	return 1;
}

/*
 * xfe_find_conn()
 * 	find a connection object in the hash table
 *      @pre the xfe_connection_lock must be held before calling this function
 */
static struct xfe_connection *
xfe_find_conn(xfe_ip_addr_t *saddr, xfe_ip_addr_t *daddr,
	      unsigned short sport, unsigned short dport,
	      unsigned char proto, bool is_v4)
{
	struct xfe_connection_create *p_sic;
	struct xfe_connection *conn;
	u32 key;

	key = fc_conn_hash(saddr, daddr, sport, dport, is_v4);

	xfe_hash_for_each_possible(fc_conn_ht, conn, node, hl, key) {
		if (conn->is_v4 != is_v4) {
			continue;
		}

		p_sic = conn->sic;

		if (p_sic->ip_proto == proto &&
		    p_sic->src_port == sport &&
		    p_sic->dest_port == dport &&
		    xfe_addr_equal(&p_sic->src_ip, saddr, is_v4) &&
		    xfe_addr_equal(&p_sic->dest_ip, daddr, is_v4)) {
			return conn;
		}
	}

	DEBUG_TRACE("connection not found\n");
	return NULL;
}

/*
 * xfe_sb_find_conn()
 * 	find a connection object in the hash table according to information of packet
 *	if not found, reverse the tuple and try again.
 *      @pre the xfe_connection_lock must be held before calling this function
 */
static struct xfe_connection *
xfe_sb_find_conn(xfe_ip_addr_t *saddr, xfe_ip_addr_t *daddr,
		 unsigned short sport, unsigned short dport,
		 unsigned char proto, bool is_v4)
{
	struct xfe_connection_create *p_sic;
	struct xfe_connection *conn;
	u32 key;

	key = fc_conn_hash(saddr, daddr, sport, dport, is_v4);

	xfe_hash_for_each_possible(fc_conn_ht, conn, node, hl, key) {
		if (conn->is_v4 != is_v4) {
			continue;
		}

		p_sic = conn->sic;

		if (p_sic->ip_proto == proto &&
		    p_sic->src_port == sport &&
		    p_sic->dest_port_xlate == dport &&
		    xfe_addr_equal(&p_sic->src_ip, saddr, is_v4) &&
		    xfe_addr_equal(&p_sic->dest_ip_xlate, daddr, is_v4)) {
			return conn;
		}
	}

	/*
	 * Reverse the tuple and try again
	 */
	key = fc_conn_hash(daddr, saddr, dport, sport, is_v4);

	xfe_hash_for_each_possible(fc_conn_ht, conn, node, hl, key) {
		if (conn->is_v4 != is_v4) {
			continue;
		}

		p_sic = conn->sic;

		if (p_sic->ip_proto == proto &&
		    p_sic->src_port == dport &&
		    p_sic->dest_port_xlate == sport &&
		    xfe_addr_equal(&p_sic->src_ip, daddr, is_v4) &&
		    xfe_addr_equal(&p_sic->dest_ip_xlate, saddr, is_v4)) {
			return conn;
		}
	}

	DEBUG_TRACE("connection not found\n");
	return NULL;
}

/*
 * xfe_add_conn()
 *	add a connection object in the hash table if no duplicate
 *	@conn connection to add
 *	@return conn if successful, NULL if duplicate
 */
static struct xfe_connection *
xfe_add_conn(struct xfe_connection *conn)
{
	struct xfe_connection_create *sic = conn->sic;
	u32 key;

	spin_lock_bh(&xfe_connections_lock);
	if (xfe_find_conn(&sic->src_ip, &sic->dest_ip, sic->src_port,
					sic->dest_port, sic->ip_proto, conn->is_v4)) {
		spin_unlock_bh(&xfe_connections_lock);
		return NULL;
	}

	key = fc_conn_hash(&sic->src_ip, &sic->dest_ip,
			   sic->src_port, sic->dest_port, conn->is_v4);

	hash_add(fc_conn_ht, &conn->hl, key);
	xfe_connections_size++;
	spin_unlock_bh(&xfe_connections_lock);

	DEBUG_TRACE(" -> adding item to xfe_connections, new size: %d\n", xfe_connections_size);

	DEBUG_TRACE("new offloadable: key: %u proto: %d src_ip: %pI4 dst_ip: %pI4, src_port: %d, dst_port: %d\n",
			key, sic->ip_proto, &(sic->src_ip), &(sic->dest_ip), sic->src_port, sic->dest_port);

	return conn;
}

/* auto offload connection once we have this many packets*/
static int offload_at_pkts = 128;

/*
 * xfe_post_routing()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
static unsigned int xfe_post_routing(struct sk_buff *skb, bool is_v4)
{
	int ret;
	struct xfe_connection_create sic;
	struct xfe_connection_create *p_sic;
	struct net_device *in;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct net_device *dev;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	struct net_device *src_dev_tmp;
	struct net_device *dest_dev_tmp;
	struct net_device *src_br_dev = NULL;
	struct net_device *dest_br_dev = NULL;
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	struct xfe_connection *conn;

	/* We only support IPv4 for now. */
	if (!is_v4) {
		return NF_ACCEPT;
	}

	/*
	 * Don't process broadcast or multicast packets.
	 */
	if (unlikely(skb->pkt_type == PACKET_BROADCAST)) {
		xfe_incr_exceptions(XFE_EXCEPTION_PACKET_BROADCAST);
		return NF_ACCEPT;
	}
	if (unlikely(skb->pkt_type == PACKET_MULTICAST)) {
		xfe_incr_exceptions(XFE_EXCEPTION_PACKET_MULTICAST);
		return NF_ACCEPT;
	}

	/*
	 * Don't process packets that are not being forwarded.
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (!in) {
		xfe_incr_exceptions(XFE_EXCEPTION_NO_IIF);
		return NF_ACCEPT;
	}

	dev_put(in);

	/*
	 * Don't process packets that aren't being tracked by conntrack.
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		xfe_incr_exceptions(XFE_EXCEPTION_NO_CT);
		DEBUG_TRACE("no conntrack connection, ignoring\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process untracked connections.
	 */
	if (unlikely((ct->status & IPS_CONFIRMED) == 0)) {
		xfe_incr_exceptions(XFE_EXCEPTION_CT_NO_TRACK);
		DEBUG_TRACE("untracked connection\n");
		return NF_ACCEPT;
	}

	/*
	 * Unconfirmed connection may be dropped by Linux at the final step,
	 * So we don't process unconfirmed connections.
	 */
	if (!nf_ct_is_confirmed(ct)) {
		xfe_incr_exceptions(XFE_EXCEPTION_CT_NO_CONFIRM);
		DEBUG_TRACE("unconfirmed connection\n");
		return NF_ACCEPT;
	}

	/*
	 * Don't process connections that require support from a 'helper' (typically a NAT ALG).
	 */
	if (unlikely(nfct_help(ct))) {
		xfe_incr_exceptions(XFE_EXCEPTION_CT_IS_ALG);
		DEBUG_TRACE("connection has helper\n");
		return NF_ACCEPT;
	}

	memset(&sic, 0, sizeof(sic));

	/*
	 * Look up the details of our connection in conntrack.
	 *
	 * Note that the data we get from conntrack is for the "ORIGINAL" direction
	 * but our packet may actually be in the "REPLY" direction.
	 */
	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	sic.ip_proto = (s32)orig_tuple.dst.protonum;

	sic.flags = 0;

	/*
	 * Get addressing information, non-NAT first
	 */
	u32 dscp;

	sic.src_ip.ip = (__be32)orig_tuple.src.u3.ip;
	sic.dest_ip.ip = (__be32)orig_tuple.dst.u3.ip;

	if (ipv4_is_multicast(sic.src_ip.ip) || ipv4_is_multicast(sic.dest_ip.ip)) {
		xfe_incr_exceptions(XFE_EXCEPTION_IS_IPV4_MCAST);
		DEBUG_TRACE("multicast address\n");
		return NF_ACCEPT;
	}

	/*
		* NAT'ed addresses - note these are as seen from the 'reply' direction
		* When NAT does not apply to this connection these will be identical to the above.
		*/
	sic.src_ip_xlate.ip = (__be32)reply_tuple.dst.u3.ip;
	sic.dest_ip_xlate.ip = (__be32)reply_tuple.src.u3.ip;

	dscp = ipv4_get_dsfield(ip_hdr(skb)) >> XT_DSCP_SHIFT;
	if (dscp) {
		sic.dest_dscp = dscp;
		sic.src_dscp = sic.dest_dscp;
		sic.flags |= XFE_CREATE_FLAG_REMARK_DSCP;
	}

	switch (sic.ip_proto) {
	case IPPROTO_TCP:
		sic.src_port = orig_tuple.src.u.tcp.port;
		sic.dest_port = orig_tuple.dst.u.tcp.port;
		sic.src_port_xlate = reply_tuple.dst.u.tcp.port;
		sic.dest_port_xlate = reply_tuple.src.u.tcp.port;

		/*
		 * Don't try to manage a non-established connection.
		 */
		if (!test_bit(IPS_ASSURED_BIT, &ct->status)) {
			xfe_incr_exceptions(XFE_EXCEPTION_TCP_NOT_ASSURED);
			DEBUG_TRACE("non-established connection\n");
			return NF_ACCEPT;
		}

		break;

	case IPPROTO_UDP:
		sic.src_port = orig_tuple.src.u.udp.port;
		sic.dest_port = orig_tuple.dst.u.udp.port;
		sic.src_port_xlate = reply_tuple.dst.u.udp.port;
		sic.dest_port_xlate = reply_tuple.src.u.udp.port;
		break;

	default:
		xfe_incr_exceptions(XFE_EXCEPTION_UNKNOW_PROTOCOL);
		DEBUG_TRACE("unhandled protocol %d\n", sic.ip_proto);
		return NF_ACCEPT;
	}

	/*
	 * Get QoS information
	 */
	if (skb->priority) {
		sic.dest_priority = skb->priority;
		sic.src_priority = sic.dest_priority;
		sic.flags |= XFE_CREATE_FLAG_REMARK_PRIORITY;
	}

	// DEBUG_TRACE("POST_ROUTE: checking new connection: %d src_ip: %pI4 dst_ip: %pI4, src_port: %d, dst_port: %d\n",
	// 	    sic.ip_proto, &sic.src_ip, &sic.dest_ip, sic.src_port, sic.dest_port);

	/*
	 * If we already have this connection in our list, skip it
	 * XXX: this may need to be optimized
	 */
	spin_lock_bh(&xfe_connections_lock);

	conn = xfe_find_conn(&sic.src_ip, &sic.dest_ip, sic.src_port, sic.dest_port, sic.ip_proto, is_v4);
	if (conn) {
		conn->hits++;

		if (!conn->offloaded) {
			if (conn->offload_permit || conn->hits >= offload_at_pkts) {
				DEBUG_TRACE("OFFLOADING CONNECTION, TOO MANY HITS\n");

				if (xfe_update_protocol(conn->sic, conn->ct) == 0) {
					spin_unlock_bh(&xfe_connections_lock);
					xfe_incr_exceptions(XFE_EXCEPTION_UPDATE_PROTOCOL_FAIL);
					DEBUG_TRACE("UNKNOWN PROTOCOL OR CONNECTION CLOSING, SKIPPING\n");
					return NF_ACCEPT;
				}

				DEBUG_TRACE("INFO: calling xfe rule creation!\n");
				spin_unlock_bh(&xfe_connections_lock);

				ret = xfe_ipv4_create_rule(conn->sic);
				if ((ret == 0) || (ret == -EADDRINUSE)) {
					conn->offloaded = 1;
				}

				return NF_ACCEPT;
			}
		}

		spin_unlock_bh(&xfe_connections_lock);
		if (conn->offloaded) {
			xfe_ipv4_update_rule(conn->sic);
		}

		DEBUG_TRACE("FOUND, SKIPPING\n");
		xfe_incr_exceptions(XFE_EXCEPTION_WAIT_FOR_ACCELERATION);
		return NF_ACCEPT;
	}

	spin_unlock_bh(&xfe_connections_lock);

	/*
	 * Get the net device and MAC addresses that correspond to the various source and
	 * destination host addresses.
	 */
	if (!xfe_find_dev_and_mac_addr(&sic.src_ip, &src_dev_tmp, sic.src_mac, is_v4)) {
		xfe_incr_exceptions(XFE_EXCEPTION_NO_SRC_DEV);
		return NF_ACCEPT;
	}
	src_dev = src_dev_tmp;

	if (!xfe_find_dev_and_mac_addr(&sic.src_ip_xlate, &dev, sic.src_mac_xlate, is_v4)) {
		xfe_incr_exceptions(XFE_EXCEPTION_NO_SRC_XLATE_DEV);
		goto done1;
	}
	dev_put(dev);

	if (!xfe_find_dev_and_mac_addr(&sic.dest_ip, &dev, sic.dest_mac, is_v4)) {
		xfe_incr_exceptions(XFE_EXCEPTION_NO_DEST_DEV);
		goto done1;
	}
	dev_put(dev);

	if (!xfe_find_dev_and_mac_addr(&sic.dest_ip_xlate, &dest_dev_tmp, sic.dest_mac_xlate, is_v4)) {
		xfe_incr_exceptions(XFE_EXCEPTION_NO_DEST_XLATE_DEV);
		goto done1;
	}
	dest_dev = dest_dev_tmp;

	/*
	 * Our devices may actually be part of a bridge interface. If that's
	 * the case then find the bridge interface instead.
	 */
	if (src_dev->priv_flags & IFF_BRIDGE_PORT) {
		src_br_dev = xfe_dev_get_master(src_dev);
		if (!src_br_dev) {
			xfe_incr_exceptions(XFE_EXCEPTION_NO_BRIDGE);
			DEBUG_TRACE("no bridge found for: %s\n", src_dev->name);
			goto done2;
		}
		src_dev = src_br_dev;
	}

	if (dest_dev->priv_flags & IFF_BRIDGE_PORT) {
		dest_br_dev = xfe_dev_get_master(dest_dev);
		if (!dest_br_dev) {
			xfe_incr_exceptions(XFE_EXCEPTION_NO_BRIDGE);
			DEBUG_TRACE("no bridge found for: %s\n", dest_dev->name);
			goto done3;
		}
		dest_dev = dest_br_dev;
	}

	sic.src_ifindex = src_dev->ifindex;
	sic.dest_ifindex = dest_dev->ifindex;

	sic.src_mtu = src_dev->mtu;
	sic.dest_mtu = dest_dev->mtu;

	if (skb->mark) {
		DEBUG_TRACE("SKB MARK NON ZERO %x\n", skb->mark);
	}
	sic.mark = skb->mark;

	conn = kmalloc(sizeof(*conn), GFP_ATOMIC);
	if (!conn) {
		printk(KERN_CRIT "ERROR: no memory for xfe\n");
		goto done4;
	}
	conn->hits = 0;
	conn->offload_permit = 0;
	conn->offloaded = 0;
	conn->is_v4 = is_v4;
	DEBUG_TRACE("Source MAC=%pM\n", sic.src_mac);
	memcpy(conn->smac, sic.src_mac, ETH_ALEN);
	memcpy(conn->dmac, sic.dest_mac_xlate, ETH_ALEN);

	p_sic = kmalloc(sizeof(*p_sic), GFP_ATOMIC);
	if (!p_sic) {
		printk(KERN_CRIT "ERROR: no memory for xfe\n");
		kfree(conn);
		goto done4;
	}

	memcpy(p_sic, &sic, sizeof(sic));
	conn->sic = p_sic;
	conn->ct = ct;

	if (!xfe_add_conn(conn)) {
		kfree(conn->sic);
		kfree(conn);
	}

	/*
	 * If we had bridge ports then release them too.
	 */
done4:
	if (dest_br_dev) {
		dev_put(dest_br_dev);
	}
done3:
	if (src_br_dev) {
		dev_put(src_br_dev);
	}
done2:
	dev_put(dest_dev_tmp);
done1:
	dev_put(src_dev_tmp);

	return NF_ACCEPT;
}

/*
 * xfe_ipv4_post_routing_hook()
 *	Called for packets about to leave the box - either locally generated or forwarded from another interface
 */
xfe_ipv4_post_routing_hook(hooknum, ops, skb, in_unused, out, okfn)
{
	return xfe_post_routing(skb, true);
}

/*
 * xfe_update_mark()
 *	updates the mark for a xfe connection
 */
static void xfe_update_mark(struct xfe_connection_mark *mark, bool is_v4)
{
	struct xfe_connection *conn;

	spin_lock_bh(&xfe_connections_lock);

	conn = xfe_find_conn(&mark->src_ip, &mark->dest_ip,
					 mark->src_port, mark->dest_port,
					 mark->protocol, is_v4);
	if (conn) {
		conn->sic->mark = mark->mark;
	}

	spin_unlock_bh(&xfe_connections_lock);
}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
/*
 * xfe_conntrack_event()
 *	Callback event invoked when a conntrack connection's state changes.
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static int xfe_conntrack_event(struct notifier_block *this,
					   unsigned long events, void *ptr)
#else
static int xfe_conntrack_event(unsigned int events, struct nf_ct_event *item)
#endif
{
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
	struct nf_ct_event *item = ptr;
#endif
	struct xfe_connection_destroy sid;
	struct nf_conn *ct = item->ct;
	struct nf_conntrack_tuple orig_tuple;
	struct xfe_connection *conn;
	bool is_v4;

	/*
	 * If we don't have a conntrack entry then we're done.
	 */
	if (unlikely(!ct)) {
		DEBUG_WARN("no ct in conntrack event callback\n");
		return NOTIFY_DONE;
	}

	/*
	 * If this is an untracked connection then we can't have any state either.
	 */
	if (unlikely((ct->status & IPS_CONFIRMED) == 0)) {
		DEBUG_TRACE("ignoring untracked conn\n");
		return NOTIFY_DONE;
	}

	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	sid.ip_proto = (s32)orig_tuple.dst.protonum;

	/*
	 * Extract information from the conntrack connection.  We're only interested
	 * in nominal connection information (i.e. we're ignoring any NAT information).
	 */
	if (likely(nf_ct_l3num(ct) == AF_INET)) {
		sid.src_ip.ip = (__be32)orig_tuple.src.u3.ip;
		sid.dest_ip.ip = (__be32)orig_tuple.dst.u3.ip;
		is_v4 = true;
	} else {
		DEBUG_TRACE("ignoring non-IPv4 connection\n");
		return NOTIFY_DONE;
	}

	switch (sid.ip_proto) {
	case IPPROTO_TCP:
		sid.src_port = orig_tuple.src.u.tcp.port;
		sid.dest_port = orig_tuple.dst.u.tcp.port;
		break;

	case IPPROTO_UDP:
		sid.src_port = orig_tuple.src.u.udp.port;
		sid.dest_port = orig_tuple.dst.u.udp.port;
		break;

	default:
		DEBUG_TRACE("unhandled protocol: %d\n", sid.ip_proto);
		return NOTIFY_DONE;
	}

	/*
	 * Check for an updated mark
	 */
	if ((events & (1 << IPCT_MARK)) && (ct->mark != 0)) {
		struct xfe_connection_mark mark;

		mark.protocol = sid.ip_proto;
		mark.src_ip = sid.src_ip;
		mark.dest_ip = sid.dest_ip;
		mark.src_port = sid.src_port;
		mark.dest_port = sid.dest_port;
		mark.mark = ct->mark;

		xfe_ipv4_mark_rule(&mark);
		xfe_update_mark(&mark, is_v4);
	}

	/*
	 * We're only interested in destroy events at this point
	 */
	if (unlikely(!(events & (1 << IPCT_DESTROY)))) {
		DEBUG_TRACE("ignoring non-destroy event\n");
		return NOTIFY_DONE;
	}

	DEBUG_TRACE("Try to clean up: proto: %d src_ip: %pI4 dst_ip: %pI4, src_port: %d, dst_port: %d\n",
		    sid.ip_proto, &sid.src_ip, &sid.dest_ip, sid.src_port, sid.dest_port);

	spin_lock_bh(&xfe_connections_lock);

	conn = xfe_find_conn(&sid.src_ip, &sid.dest_ip, sid.src_port, sid.dest_port, sid.ip_proto, is_v4);
	if (conn) {
		DEBUG_TRACE("Free connection\n");

		hash_del(&conn->hl);
		xfe_connections_size--;
		kfree(conn->sic);
		kfree(conn);
	} else {
		xfe_incr_exceptions(XFE_EXCEPTION_CT_DESTROY_MISS);
	}

	spin_unlock_bh(&xfe_connections_lock);

	xfe_ipv4_destroy_rule(&sid);

	return NOTIFY_DONE;
}

/*
 * Netfilter conntrack event system to monitor connection tracking changes
 */
#ifdef CONFIG_NF_CONNTRACK_CHAIN_EVENTS
static struct notifier_block xfe_conntrack_notifier = {
	.notifier_call = xfe_conntrack_event,
};
#else
static struct nf_ct_event_notifier xfe_conntrack_notifier = {
	.fcn = xfe_conntrack_event,
};
#endif
#endif

/*
 * Structure to establish a hook into the post routing netfilter point - this
 * will pick up local outbound and packets going from one interface to another.
 *
 * Note: see include/linux/netfilter_ipv4.h for info related to priority levels.
 * We want to examine packets after NAT translation and any ALG processing.
 */
static struct nf_hook_ops xfe_ops_post_routing[] __read_mostly = {
	XFE_IPV4_NF_POST_ROUTING_HOOK(__xfe_ipv4_post_routing_hook),
};

/*
 * xfe_sync_rule()
 *	Synchronize a connection's state.
 */
static void xfe_sync_rule(struct xfe_connection_sync *sis)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	XFE_NF_CONN_ACCT(acct);

	/*
	 * Create a tuple so as to be able to look up a connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u.all = (__be16)sis->src_port;
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (u8)sis->protocol;
	tuple.dst.u.all = (__be16)sis->dest_port;

	tuple.src.u3.ip = sis->src_ip.ip;
	tuple.dst.u3.ip = sis->dest_ip.ip;
	tuple.src.l3num = AF_INET;

	DEBUG_TRACE("update connection - p: %d, s: %pI4:%u, d: %pI4:%u\n",
		    (int)tuple.dst.protonum,
		    &tuple.src.u3.ip, (unsigned int)ntohs(tuple.src.u.all),
		    &tuple.dst.u3.ip, (unsigned int)ntohs(tuple.dst.u.all));

	/* Native bridge NOT supported (can't update statistics) */
	/*
	 * Update packet count for ingress on bridge device
	 */
	// if (skip_to_bridge_ingress) {
	// 	struct rtnl_link_stats64 nlstats;
	// 	nlstats.tx_packets = 0;
	// 	nlstats.tx_bytes = 0;

	// 	if (src_dev && IFF_EBRIDGE &&
	// 	    (sis->src_new_packet_count || sis->src_new_byte_count)) {
	// 		nlstats.rx_packets = sis->src_new_packet_count;
	// 		nlstats.rx_bytes = sis->src_new_byte_count;
	// 		spin_lock_bh(&xfe_connections_lock);
	// 		br_dev_update_stats(src_dev, &nlstats);
	// 		spin_unlock_bh(&xfe_connections_lock);
	// 	}
	// 	if (dest_dev && IFF_EBRIDGE &&
	// 	    (sis->dest_new_packet_count || sis->dest_new_byte_count)) {
	// 		nlstats.rx_packets = sis->dest_new_packet_count;
	// 		nlstats.rx_bytes = sis->dest_new_byte_count;
	// 		spin_lock_bh(&xfe_connections_lock);
	// 		br_dev_update_stats(dest_dev, &nlstats);
	// 		spin_unlock_bh(&xfe_connections_lock);
	// 	}
	// }

	/*
	 * Look up conntrack connection
	 */
	h = nf_conntrack_find_get(&init_net, XFE_NF_CT_DEFAULT_ZONE, &tuple);
	if (unlikely(!h)) {
		DEBUG_TRACE("no connection found\n");
		return;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);

	/*
	 * Only update if this is not a fixed timeout
	 */
	if (!test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		spin_lock_bh(&ct->lock);
		/* TODO: handle timeout properly */
		// ct->timeout.expires += sis->delta_jiffies;
		WRITE_ONCE(ct->timeout, nfct_time_stamp + HZ * 2); // 2 OK?
		spin_unlock_bh(&ct->lock);
	}

	acct = nf_conn_acct_find(ct);
	if (acct) {
		spin_lock_bh(&ct->lock);
		atomic64_add(sis->src_new_packet_count, &XFE_ACCT_COUNTER(acct)[IP_CT_DIR_ORIGINAL].packets);
		atomic64_add(sis->src_new_byte_count, &XFE_ACCT_COUNTER(acct)[IP_CT_DIR_ORIGINAL].bytes);
		atomic64_add(sis->dest_new_packet_count, &XFE_ACCT_COUNTER(acct)[IP_CT_DIR_REPLY].packets);
		atomic64_add(sis->dest_new_byte_count, &XFE_ACCT_COUNTER(acct)[IP_CT_DIR_REPLY].bytes);
		spin_unlock_bh(&ct->lock);
	}

	/* We don't care about this right now */
	// switch (sis->protocol) {
	// case IPPROTO_TCP:
	// 	spin_lock_bh(&ct->lock);
	// 	if (ct->proto.tcp.seen[0].td_maxwin < sis->src_td_max_window) {
	// 		ct->proto.tcp.seen[0].td_maxwin = sis->src_td_max_window;
	// 	}
	// 	if ((s32)(ct->proto.tcp.seen[0].td_end - sis->src_td_end) < 0) {
	// 		ct->proto.tcp.seen[0].td_end = sis->src_td_end;
	// 	}
	// 	if ((s32)(ct->proto.tcp.seen[0].td_maxend - sis->src_td_max_end) < 0) {
	// 		ct->proto.tcp.seen[0].td_maxend = sis->src_td_max_end;
	// 	}
	// 	if (ct->proto.tcp.seen[1].td_maxwin < sis->dest_td_max_window) {
	// 		ct->proto.tcp.seen[1].td_maxwin = sis->dest_td_max_window;
	// 	}
	// 	if ((s32)(ct->proto.tcp.seen[1].td_end - sis->dest_td_end) < 0) {
	// 		ct->proto.tcp.seen[1].td_end = sis->dest_td_end;
	// 	}
	// 	if ((s32)(ct->proto.tcp.seen[1].td_maxend - sis->dest_td_max_end) < 0) {
	// 		ct->proto.tcp.seen[1].td_maxend = sis->dest_td_max_end;
	// 	}
	// 	spin_unlock_bh(&ct->lock);
	// 	break;
	// }

	/*
	 * Release connection
	 */
	nf_ct_put(ct);
}

/*
 * xfe_device_event()
 */
static int xfe_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = XFE_DEV_EVENT_PTR(ptr);

	if (dev && (event == NETDEV_DOWN)) {
		xfe_ipv4_destroy_all_rules_for_dev(dev);
	}

	return NOTIFY_DONE;
}

/*
 * xfe_inet_event()
 */
static int xfe_inet_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ((struct in_ifaddr *)ptr)->ifa_dev->dev;

	if (dev && (event == NETDEV_DOWN)) {
		xfe_ipv4_destroy_all_rules_for_dev(dev);
	}

	return NOTIFY_DONE;
}

/*
 * xfe_get_offload_at_pkts()
 */
static ssize_t xfe_get_offload_at_pkts(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	return snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", offload_at_pkts);
}

/*
 * xfe_set_offload_at_pkts()
 */
static ssize_t xfe_set_offload_at_pkts(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t size)
{
	long new;
	int ret;

	ret = kstrtol(buf, 0, &new);
	if (ret == -EINVAL || ((int)new != new))
		return -EINVAL;

	offload_at_pkts = new;

	return size;
}

/*
 * xfe_get_debug_info()
 */
static ssize_t xfe_get_debug_info(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	size_t len = 0;
	struct xfe_connection *conn;
	u32 i;

	spin_lock_bh(&xfe_connections_lock);
	len += scnprintf(buf, PAGE_SIZE - len, "size=%d offload=%d offload_no_match=%d"
			" offloaded=%d done=%d offloaded_fail=%d done_fail=%d\n",
			xfe_connections_size,
			atomic_read(&offload_msgs),
			atomic_read(&offload_no_match_msgs),
			atomic_read(&offloaded_msgs),
			atomic_read(&done_msgs),
			atomic_read(&offloaded_fail_msgs),
			atomic_read(&done_fail_msgs));
	xfe_hash_for_each(fc_conn_ht, i, node, conn, hl) {
		len += scnprintf(buf + len, PAGE_SIZE - len,
				"o=%d, p=%d [%pM]:%pI4:%u %pI4:%u:[%pM] m=%08x h=%d\n",
				conn->offloaded,
				conn->sic->ip_proto,
				conn->sic->src_mac,
				&conn->sic->src_ip,
				conn->sic->src_port,
				&conn->sic->dest_ip,
				conn->sic->dest_port,
				conn->sic->dest_mac_xlate,
				conn->sic->mark,
				conn->hits);
	}
	spin_unlock_bh(&xfe_connections_lock);

	return len;
}

/*
 * xfe_get_skip_bridge_ingress()
 */
static ssize_t xfe_get_skip_bridge_ingress(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	return snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", skip_to_bridge_ingress);
}

/*
 * xfe_set_skip_bridge_ingress()
 */
static ssize_t xfe_set_skip_bridge_ingress(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t size)
{
	long new;
	int ret;

	ret = kstrtol(buf, 0, &new);
	if (ret == -EINVAL || ((int)new != new))
		return -EINVAL;

	skip_to_bridge_ingress = new ? 1 : 0;

	return size;
}

/*
 * xfe_get_exceptions
 * 	dump exception counters
 */
static ssize_t xfe_get_exceptions(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	int idx, len;
	struct xfe *sc = &__sc;

	spin_lock_bh(&sc->lock);
	for (len = 0, idx = 0; idx < XFE_EXCEPTION_MAX; idx++) {
		if (sc->exceptions[idx]) {
			len += snprintf(buf + len, (ssize_t)(PAGE_SIZE - len), "%s = %d\n", xfe_exception_events_string[idx], sc->exceptions[idx]);
		}
	}
	spin_unlock_bh(&sc->lock);

	return len;
}

/*
 * sysfs attributes.
 */
static const struct device_attribute xfe_offload_at_pkts_attr =
	__ATTR(offload_at_pkts, S_IWUSR | S_IRUGO, xfe_get_offload_at_pkts, xfe_set_offload_at_pkts);
static const struct device_attribute xfe_debug_info_attr =
	__ATTR(debug_info, S_IRUGO, xfe_get_debug_info, NULL);
static const struct device_attribute xfe_skip_bridge_ingress =
	__ATTR(skip_to_bridge_ingress, S_IWUSR | S_IRUGO, xfe_get_skip_bridge_ingress, xfe_set_skip_bridge_ingress);
static const struct device_attribute xfe_exceptions_attr =
	__ATTR(exceptions, S_IRUGO, xfe_get_exceptions, NULL);

/*
 * xfe_init()
 */
static int __init xfe_init(void)
{
	struct xfe *sc = &__sc;
	struct netlink_kernel_cfg cfg = {
        .input = xfe_netlink_recv_msg,
    };
	int result = -1;

	printk(KERN_ALERT "xfe: starting up\n");
	DEBUG_INFO("XFE CM init\n");

	hash_init(fc_conn_ht);

	/*
	 * Create sys/xfe
	 */
	sc->sys_xfe = kobject_create_and_add("xfe", NULL);
	if (!sc->sys_xfe) {
		DEBUG_ERROR("failed to register xfe\n");
		goto exit1;
	}

	result = sysfs_create_file(sc->sys_xfe, &xfe_offload_at_pkts_attr.attr);
	if (result) {
		DEBUG_ERROR("failed to register offload at pkgs: %d\n", result);
		goto exit2;
	}

	result = sysfs_create_file(sc->sys_xfe, &xfe_debug_info_attr.attr);
	if (result) {
		DEBUG_ERROR("failed to register debug dev: %d\n", result);
		sysfs_remove_file(sc->sys_xfe, &xfe_offload_at_pkts_attr.attr);
		goto exit2;
	}

	result = sysfs_create_file(sc->sys_xfe, &xfe_skip_bridge_ingress.attr);
	if (result) {
		DEBUG_ERROR("failed to register skip bridge on ingress: %d\n", result);
		sysfs_remove_file(sc->sys_xfe, &xfe_offload_at_pkts_attr.attr);
		sysfs_remove_file(sc->sys_xfe, &xfe_debug_info_attr.attr);
		goto exit2;
	}

	result = sysfs_create_file(sc->sys_xfe, &xfe_exceptions_attr.attr);
	if (result) {
		DEBUG_ERROR("failed to register exceptions file: %d\n", result);
		sysfs_remove_file(sc->sys_xfe, &xfe_offload_at_pkts_attr.attr);
		sysfs_remove_file(sc->sys_xfe, &xfe_debug_info_attr.attr);
		sysfs_remove_file(sc->sys_xfe, &xfe_skip_bridge_ingress.attr);
		goto exit2;
	}

	sc->dev_notifier.notifier_call = xfe_device_event;
	sc->dev_notifier.priority = 1;
	register_netdevice_notifier(&sc->dev_notifier);

	sc->inet_notifier.notifier_call = xfe_inet_event;
	sc->inet_notifier.priority = 1;
	register_inetaddr_notifier(&sc->inet_notifier);

	/*
	 * Register our netfilter hooks.
	 */
	result = nf_register_net_hooks(&init_net, xfe_ops_post_routing, ARRAY_SIZE(xfe_ops_post_routing));
	if (result < 0) {
		DEBUG_ERROR("can't register nf post routing hook: %d\n", result);
		goto exit3;
	}

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	/*
	 * Register a notifier hook to get fast notifications of expired connections.
	 */
	result = nf_conntrack_register_notifier(&init_net, &xfe_conntrack_notifier);
	if (result < 0) {
		DEBUG_ERROR("can't register nf notifier hook: %d\n", result);
		goto exit4;
	}
#endif

	nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (nl_sock == NULL)
    {
        DEBUG_ERROR("error creating netlink socket\n");
        goto exit5;
    }

	printk(KERN_ALERT "xfe: registered\n");

	spin_lock_init(&sc->lock);

	/*
	 * Hook the shortcut sync callback.
	 */
	/* TODO .... */
	return 0;

exit6:
	netlink_kernel_release(nl_sock);

exit5:
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	nf_conntrack_unregister_notifier(&init_net, &xfe_conntrack_notifier);

exit4:
#endif
	nf_unregister_net_hooks(&init_net, xfe_ops_post_routing, ARRAY_SIZE(xfe_ops_post_routing));

exit3:
	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);
	sysfs_remove_file(sc->sys_xfe, &xfe_offload_at_pkts_attr.attr);
	sysfs_remove_file(sc->sys_xfe, &xfe_debug_info_attr.attr);
	sysfs_remove_file(sc->sys_xfe, &xfe_skip_bridge_ingress.attr);
	sysfs_remove_file(sc->sys_xfe, &xfe_exceptions_attr.attr);

exit2:
	kobject_put(sc->sys_xfe);

exit1:
	return result;
}

/*
 * xfe_exit()
 */
static void __exit xfe_exit(void)
{
	struct xfe *sc = &__sc;

	DEBUG_INFO("XFE CM exit\n");
	printk(KERN_ALERT "xfe: shutting down\n");

	/*
	 * Unregister our sync callback.
	 */
	/* TODO .... */

	/*
	 * Wait for all callbacks to complete.
	 */
	rcu_barrier();

	/*
	 * Destroy all connections.
	 */
	xfe_ipv4_destroy_all_rules_for_dev(NULL);

	/*
	 * Clean up netlink
	 */
	netlink_kernel_release(nl_sock);

	/*
	 * Clean up BPF
	 */
	xfe_bpf_free();

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	nf_conntrack_unregister_notifier(&init_net, &xfe_conntrack_notifier);

#endif
	nf_unregister_net_hooks(&init_net, xfe_ops_post_routing, ARRAY_SIZE(xfe_ops_post_routing));

	unregister_inetaddr_notifier(&sc->inet_notifier);
	unregister_netdevice_notifier(&sc->dev_notifier);

	kobject_put(sc->sys_xfe);
}

module_init(xfe_init);
module_exit(xfe_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tomaz Hribernik");
MODULE_DESCRIPTION("XDP forwarding engine.");
MODULE_VERSION("0.01");
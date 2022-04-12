#include "xfe_types.h"
#include "xfe_kmod.h"

static struct bpf_prog *prog = NULL;

static int run_bpf(enum xfe_kmod_action action, void *data, size_t data_len, struct sk_buff **skb_persist)
{
    struct xfe_kmod_message *msg;
    long unsigned int msg_len = sizeof(*msg);
    struct sk_buff *skb;
    int code;

    if (!prog) {
        printk(KERN_INFO "xfe netlink: no BPF program\n");
        return -1;
    }

    /* Allocate new SKB */
    skb = alloc_skb(msg_len, GFP_ATOMIC);

    /* Copy data into SKB */
    msg = skb_put(skb, msg_len);
    msg->action = action;
    memcpy(&msg->create, data, data_len);

    /* These are the pointers bpf uses for data and data_end */
    bpf_compute_data_pointers(skb);

    /* Run BPF program */
    code = BPF_PROG_RUN(prog, skb);

    /* Check if we need to keep the skb for our caller to handle */
    if (skb_persist != NULL) {
        *skb_persist = skb;
    } else {
        /* Cleanup */
        kfree_skb(skb);
    }

    return code;
}

int xfe_set_xdp_program(int user_fd) {
    struct bpf_prog *_prog;

    /* Free old BPF program */
    if (prog) {
        bpf_prog_put(prog);
        prog = NULL;
    }

    /* Check if the FD user passed is valid */
    if (user_fd < 0)
        return 0;

    /* Lookup new BPF program */
    _prog = bpf_prog_get_type(user_fd, BPF_PROG_TYPE_SCHED_CLS);
    if (IS_ERR(_prog)) {
        printk(KERN_INFO "xfe_set_xdp_program: bpf_prog_get_type returned ERROR\n");
        return -1;
    }

    prog = _prog;
    printk(KERN_INFO "xfe_set_xdp_program: Successfuly set XDP program\n");
    return 0;
}

int xfe_ipv4_create_rule(struct xfe_connection_create *sic) {
    printk("xfe_ipv4_create_rule called with params\n");

    printk("New connection, MAC addresses %pM -> %pM\n", sic->xlate_src_mac, sic->xlate_dest_mac);
    return run_bpf(XFE_KMOD_INSERT, sic, sizeof(*sic), NULL);
}

void xfe_ipv4_destroy_rule(struct xfe_connection_destroy *sid) {
    printk("xfe_ipv4_destroy_rule called with params\n");

    run_bpf(XFE_KMOD_DESTROY, sid, sizeof(*sid), NULL);
}

void xfe_ipv4_destroy_all_rules_for_dev(struct net_device *dev) {
    /* Default ifindex -1 indicates flush ALL */
    __u32 ifindex = -1;

    printk("xfe_ipv4_destroy_all_rules_for_dev called for dev %s\n", dev->name);

    /* If we get an interface, flush only rules on that interface */
    if (dev != NULL) {
        ifindex = dev->ifindex;
    }
    run_bpf(XFE_KMOD_FLUSH, &ifindex, sizeof(ifindex), NULL);
}

void xfe_ipv4_update_rule(struct xfe_connection_create *sic) {
    printk("xfe_ipv4_update_rule called with params\n");

    run_bpf(XFE_KMOD_UPDATE, sic, sizeof(*sic), NULL);
}

void xfe_ipv4_mark_rule(struct xfe_connection_mark *mark) {
    printk("xfe_ipv4_mark_rule called with params\n");

    run_bpf(XFE_KMOD_MARK, mark, sizeof(*mark), NULL);
}

int xfe_ipv4_sync_rules(struct xfe_connection_sync *syncs, int count, struct sk_buff **ret) {
    printk("xfe_ipv4_sync_rules called with params\n");

    return run_bpf(XFE_KMOD_SYNC, syncs, sizeof(*syncs) * count, ret);
}

/*
 * xfe_netlink_recv_msg
 *  netlink receive handler
 */
void xfe_netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct xfe_nl_msg *msg;
    int pid;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /* pid of sending process */
    msg = (struct xfe_nl_msg *)nlmsg_data(nlh);

    if (msg->msg_type == XFE_MSG_PROG_FD) {
        xfe_set_xdp_program(msg->msg_value);
    } else {
        printk(KERN_INFO "xfe netlink: Unknown message type %u\n", msg->msg_type);
    }
}

void xfe_bpf_free(void)
{
    if (prog) {
        bpf_prog_put(prog);
    }
}

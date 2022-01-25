#include <net/sock.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include "xfe_types.h"

#define NETLINK_TEST 17

struct sock *nl_sock = NULL;
struct bpf_prog *prog = NULL;

static int run_bpf(struct xfe_kmod_message *msg)
{
    long unsigned int msg_len = sizeof(*msg);
    struct sk_buff *skb;
    int code;

    if (!prog)
    {
        printk(KERN_INFO "xfe netlink: no BPF program\n");
        return -1;
    }

    /* Allocate new SKB */
    skb = alloc_skb(msg_len, GFP_ATOMIC);
    memcpy(skb_put(skb, msg_len), msg, msg_len);
    bpf_compute_data_pointers(skb);

    /* Run BPF program */
    code = BPF_PROG_RUN(prog, skb);

    /* Cleanup */
    kfree_skb(skb);

    return code;
}

static void netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct xfe_nl_msg *msg;
    int pid;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /* pid of sending process */
    msg = (struct xfe_nl_msg *)nlmsg_data(nlh);

    if (msg->msg_type == XFE_MSG_PROG_FD)
    {
        int user_fd = msg->msg_value;
        struct bpf_prog *_prog;

        /* Free old BPF program */
        if (prog) {
            bpf_prog_put(prog);
            prog = NULL;
        }

        /* Check if the FD user passed is valid */
        if (user_fd < 0)
            goto out;

        /* Lookup new BPF program */
        _prog = bpf_prog_get_type(user_fd, BPF_PROG_TYPE_SCHED_CLS);
        if (IS_ERR(_prog))
        {
            printk(KERN_INFO "xfe netlink: bpf_prog_get_type returned ERROR\n");
            goto out;
        }

        prog = _prog;
    }
    else
    {
        printk(KERN_INFO "xfe netlink: Unknown message type %u\n", msg->msg_type);
    }

out:
    return;
}

static int __init xfe_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
    };

    nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (nl_sock == NULL)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -1;
    }

    printk(KERN_INFO "XFE init\n");

    return 0;
}

static void __exit xfe_exit(void)
{
    if (nl_sock)
    {
        netlink_kernel_release(nl_sock);
    }
    if (prog) {
        bpf_prog_put(prog);
    }

    printk(KERN_INFO "XFE exit\n");
}

module_init(xfe_init);
module_exit(xfe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomaz Hribernik");
MODULE_DESCRIPTION("XDP forwarding engine.");
MODULE_VERSION("0.01");

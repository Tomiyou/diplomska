#include <net/sock.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include "xfe_types.h"

#define NETLINK_TEST 17

struct sock *nl_sock = NULL;

bool initialized = false;
bool fd_valid = false;
struct fd f;
int prog_fd;

static void netlink_recv_msg(struct sk_buff *skb)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    struct xfe_nl_msg *msg;
    int pid;
    int res;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /* pid of sending process */
    msg = (struct xfe_nl_msg *)nlmsg_data(nlh);

    if (msg->msg_type == XFE_MSG_MAP_FD) {
        long unsigned int msg_len = sizeof(*msg);
        int user_fd = msg->msg_value;
        printk(KERN_INFO "xfe netlink: Received FD %d\n", user_fd);

        /* Allocate new SKB */
        struct sk_buff *skb = alloc_skb(msg_len, GFP_ATOMIC);
        memcpy(skb_put(skb, msg_len), msg, msg_len);
        printk("XFE_MSG_RUN_PROG head: %p (%p), end: %u (%u %lu)\n", skb->head, skb->data, skb->end, skb->len, msg_len);
        printk("XFE_MSG_RUN_PROG head: %p (%p), end: %u (%u %lu)\n", skb->head, skb->data, skb->end, skb->len, msg_len);

        /* Get bpf_prog using FD */
        struct bpf_prog *prog = bpf_prog_get_type(user_fd, BPF_PROG_TYPE_SCHED_CLS);
        if (IS_ERR(prog)) {
            printk(KERN_INFO "xfe netlink: bpf_prog_get_type ERROR\n");
        } else {
            int code = BPF_PROG_RUN(prog, skb);
            printk(KERN_INFO "BPF_PROG_RUN returned code %d\n", code);
            bpf_prog_put(prog);
        }

        kfree_skb(skb);
        initialized = true;
    } else if (msg->msg_type == XFE_MSG_MAP_LOOKUP) {
        __u32 key = msg->msg_value;
        struct xfe_flow flow;
        int err;

        printk(KERN_INFO "xfe netlink: Looking up key %u\n", key);

        err = accel_map_lookup_elem(f, &key, &flow, 0);
        if (err != 0) {
            printk(KERN_INFO "xfe netlink: accel_map_lookup_elem FAILED %d\n", err);
        } else {
            printk(KERN_INFO "xfe netlink: accel_map_lookup_elem FOUND %u\n", flow.rx_packet_count);
        }
    } else if (msg->msg_type == XFE_MSG_MAP_DELETE) {
        __u32 key = msg->msg_value;
        int err;

        printk(KERN_INFO "xfe netlink: Deleting key %u\n", key);

        err = accel_map_delete_elem(f, &key, 0);
        if (err != 0) {
            printk(KERN_INFO "xfe netlink: accel_map_delete_elem FAILED %d\n", err);
        } else {
            printk(KERN_INFO "xfe netlink: accel_map_delete_elem SUCCEEDED");
        }
    } else if (msg->msg_type == XFE_MSG_MAP_UPDATE) {
        __u32 key = msg->msg_value;
        struct xfe_flow flow;
        int err;

        printk(KERN_INFO "xfe netlink: Inserting key %u and value %u\n", key, flow.rx_packet_count);

        err = accel_map_update_elem(f, &key, &flow, 0);
        if (err != 0) {
            printk(KERN_INFO "xfe netlink: accel_map_update_elem FAILED %d\n", err);
        } else {
            printk(KERN_INFO "xfe netlink: accel_map_update_elem SUCCEEDED\n");
        }
    } else {
        printk(KERN_INFO "xfe netlink: Unknown message type %u\n", msg->msg_value);
    }
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
    if (fd_valid)
    {
        printk(KERN_INFO "xfe netlink: Closing FD\n");
        fdput(f);
    }

    printk(KERN_INFO "XFE exit\n");
}

module_init(xfe_init);
module_exit(xfe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomaz Hribernik");
MODULE_DESCRIPTION("XDP forwarding engine.");
MODULE_VERSION("0.01");

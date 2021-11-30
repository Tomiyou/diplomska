#include <net/sock.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "xfe_types.h"

#define NETLINK_TEST 17

struct sock *nl_sock = NULL;

unsigned int map_fd = 0;
bool initialized = false;

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
        map_fd = msg->msg_value;
        initialized = true;
        printk(KERN_INFO "xfe netlink: Received FD %u\n", map_fd);
    }

    // printk(KERN_INFO "netlink_test: Received from pid %d: %s\n", pid, msg);
}

static int __init xfe_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
    };

    nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (!nl_sock)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    printk(KERN_INFO "XFE init\n");

    return 0;
}

static void __exit xfe_exit(void)
{
    printk(KERN_INFO "XFE exit\n");
}

module_init(xfe_init);
module_exit(xfe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomaz Hribernik");
MODULE_DESCRIPTION("XDP forwarding engine.");
MODULE_VERSION("0.01");

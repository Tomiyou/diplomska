#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/netlink.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xfe_types.h"

#define MAX_PAYLOAD 1024 /* maximum payload size */
#define NETLINK_TEST 17
#define OBJ_PIN_PATH "/sys/fs/bpf/xfe"

struct sockaddr_nl src_addr;
struct sockaddr_nl dest_addr;
int sock_fd;

static int load_accelerator(const char* obj_path)
{
    struct bpf_program *prog;
    struct bpf_object *obj;
    struct bpf_map *map;
    long error;

    /* Open BPF object */
    obj = bpf_object__open(obj_path);
    error = libbpf_get_error(obj);
    if (error)
    {
        printf("LIBBPF error in function 'bpf_object__open': %ld.\n", error);
        return -1;
    }

    /* Walk through found programs and maps */
    printf("Opened object '%s'\n", bpf_object__name(obj));
    printf("XFE Programs:\n");
    bpf_object__for_each_program(prog, obj)
    {
        const char *title = bpf_program__section_name(prog);
        int error = bpf_program__set_xdp(prog);

        printf(" - %s (set program type to xdp)\n", title);

        if (error)
        {
            printf(" +--> Failed to set '%s' prog type: %s\n", title);
            return -1;
        }
    }

    printf("XFE maps:\n");
    bpf_map__for_each(map, obj)
    {
        const char *name = bpf_map__name(map);
        printf(" - %s\n", name);
    }

    /* Load programs and maps */
    error = bpf_object__load(obj);
    if (error)
    {
        printf("LIBBPF error in function 'bpf_object__load': %ld.\n", error);
        goto close;
    }

    /* Pin programs and maps */
    error = bpf_object__pin(obj, OBJ_PIN_PATH);
    if (error)
    {
        printf("LIBBPF error in function 'bpf_object__pin': %ld.\n", error);
        goto close;
    }

    /* No need to keep object in memory anymore */
    error = bpf_object__unload(obj);
    if (error)
    {
        printf("LIBBPF error in function 'bpf_object__unload': %ld.\n", error);
        goto close;
    }

close:
    bpf_object__close(obj);

    return error;
}

static int init_netlink()
{
    /* Open netlink socket */
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if (sock_fd < 0)
    {
        printf("socket() error: %s\n", strerror(errno));
        return -1;
    }

    /* Set socket source address (self) */
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */
    src_addr.nl_groups = 0;     /* not in mcast groups */
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    /* Set socket destination address (kernel module) */
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;    /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */
}

static int deinit_netlink()
{
    close(sock_fd);
    return 0;
}

static int send_netlink(void *data, size_t data_len)
{
    struct nlmsghdr *nlh;
    struct msghdr msg;
    struct iovec iov;
    int rc;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(data_len));

    /* Fill the netlink message header */
    nlh->nlmsg_len = NLMSG_SPACE(data_len);
    nlh->nlmsg_pid = getpid(); /* self pid */
    nlh->nlmsg_flags = 0;

    /* Fill in the netlink message payload */
    memcpy(NLMSG_DATA(nlh), data, data_len);

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    rc = sendmsg(sock_fd, &msg, 0);
    if (rc < 0)
    {
        printf("netlink sendmsg() error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int set_map_fd(unsigned int map_fd)
{
    struct xfe_nl_msg xfe_msg = {
        XFE_MSG_MAP_FD,
        0};
    int fd;

    // fd = bpf_obj_get(OBJ_PIN_PATH "/%s", map_name);
    if (fd < 1) {
        printf("Could not load XDP map\n");
        return -1;
    }

    xfe_msg.msg_value = fd;

    if (send_netlink(&xfe_msg, sizeof(xfe_msg)))
    {
        printf("Could not initialize netlink.\n");
        return -1;
    }

    return 0;
}

int init_kmod(const char* obj_path)
{
    int err;

    // TODO: Check if already initialized (xdp pinned, etc)

    err = init_netlink();
    if (err)
    {
        printf("Could not initialize netlink.\n");
        return err;
    }

    /* Load accelerator */
    err = load_accelerator(obj_path);
    if (err)
    {
        printf("Could not load XDP accelerator.\n");
        goto exit;
    }

    /* Initialize kernel module */
    // err = set_map_fd(map_fd);
    // if (err)
    // {
    //     printf("Could not initialize kernel module.\n");
    //     goto exit;
    // }

exit:
    deinit_netlink();
    return err;
}

int main(int argc, char **argv)
{
    char* xfe_obj_path = getenv("XFE_OBJ_PATH");
    const char* cmd;
    int err = 0;
    int i;

    /* Check if XFE_OBJ_PATH environment variable is set */
    if (!xfe_obj_path)
    {
        printf("XFE_OBJ_PATH environment variable is NOT set\n");
        return -1;
    }

    /* Check if proper command argument was provided */
    if (argc < 2)
    {
        printf("Usage: command [arguments...]\n");
        return -1;
    }

    cmd = argv[1];

    if (strncmp(cmd, "init", 4) == 0)
    {
        /* Init accelerator */
        printf("Initializing accelerator\n");
        err = init_kmod(xfe_obj_path);
    }
    else if (strncmp(cmd, "attach", 6) == 0)
    {
        /* Attach XDP to interface */
        if (argc < 3)
        {
            printf("Attach command requires interface name as argument\n");
            return -1;
        }

        printf("Attaching accelerator to interface %s\n", argv[2]);
        // attach_interface()
    }
    else
    {
        printf("No command specified.\n");
    }

    return err;
}

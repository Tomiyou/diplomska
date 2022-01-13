enum xfe_nl_msg_type {
    XFE_MSG_MAP_FD,
    XFE_MSG_MAP_LOOKUP,
    XFE_MSG_MAP_DELETE,
    XFE_MSG_MAP_UPDATE
};

struct xfe_nl_msg {
    enum xfe_nl_msg_type msg_type;
    unsigned int msg_value;
};

struct xfe_flow {
    unsigned long stats;
};

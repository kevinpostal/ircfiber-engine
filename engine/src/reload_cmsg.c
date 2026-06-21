#include <sys/socket.h>
#include <stddef.h>

size_t ircfiber_cmsg_space(size_t len) { return CMSG_SPACE(len); }
struct cmsghdr *ircfiber_cmsg_firsthdr(struct msghdr *m) { return CMSG_FIRSTHDR(m); }
struct cmsghdr *ircfiber_cmsg_nxthdr(struct msghdr *m, struct cmsghdr *c) { return CMSG_NXTHDR(m, c); }
unsigned char *ircfiber_cmsg_data(struct cmsghdr *c) { return CMSG_DATA(c); }

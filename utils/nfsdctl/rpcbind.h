/*
 * rpcbind.h -- register nfsd listeners with the local rpcbind
 */

#ifndef _UTILS_NFSDCTL_RPCBIND_H
#define _UTILS_NFSDCTL_RPCBIND_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#ifndef NFS_PROGRAM
#define NFS_PROGRAM		100003
#endif
#ifndef NFS_ACL_PROGRAM
#define NFS_ACL_PROGRAM		100227
#endif

/*
 * All of the existing netids are short strings (3-4 chars), but let's allow
 * for up to 16.
 */
#define MAX_CLASS_NAME_LEN	16

struct server_socket {
	struct sockaddr_storage	ss;
	char name[MAX_CLASS_NAME_LEN];
	bool active;
};

/* One [program, version] that the kernel would have registered. */
struct nfsd_rpcb_prog {
	uint32_t	program;
	uint32_t	version;
	uint32_t	flags;
};

void nfsd_rpcb_unset_all(void);
void nfsd_rpcb_register(const struct server_socket *listeners, int nlisteners,
			const struct nfsd_rpcb_prog *progs, int nprogs);

#endif /* _UTILS_NFSDCTL_RPCBIND_H */

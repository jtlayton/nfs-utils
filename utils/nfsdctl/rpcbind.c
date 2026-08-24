/*
 * rpcbind.c -- register nfsd listeners with the local rpcbind
 *
 * A kernel that accepts NFSD_A_SERVER_SOCK_USERSPACE_RPCBIND makes no
 * rpcbind call of its own, so this program makes them instead. The kernel
 * used to do this under nfsd_mutex, where a slow rpcbind stalled every
 * other NFSD netlink operation.
 *
 * lockd still registers NLM itself, so nothing here touches it.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include <rpc/rpc.h>

#ifdef HAVE_LIBTIRPC
#include <rpc/rpcb_clnt.h>
#include <netconfig.h>
#endif	/* HAVE_LIBTIRPC */

#include "nfslib.h"
#include "rpcmisc.h"
#include "sockaddr.h"
#include "xlog.h"
#include "rpcbind.h"

#ifdef USE_SYSTEM_NFSD_NETLINK_H
#include <linux/nfsd_netlink.h>
#else
#include "nfsd_netlink.h"
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#endif

/*
 * Programs to clear at shutdown. There is no reply to read at that point,
 * so clear a superset. rpcb_unset() of an absent entry does nothing.
 */
static const struct {
	rpcprog_t	program;
	rpcvers_t	version;
} nfsd_rpcb_all[] = {
	{ NFS_PROGRAM,		2 },
	{ NFS_PROGRAM,		3 },
	{ NFS_PROGRAM,		4 },
	{ NFS_ACL_PROGRAM,	2 },
	{ NFS_ACL_PROGRAM,	3 },
};

/**
 * nfsd_rpcb_unset_all - remove every nfsd entry from the local rpcbind
 *
 * rpcb_unset() matches [program, version, netid] and takes no address, so
 * one call clears every netid. This mirrors the svc_unregister() sweep that
 * svc_rpcb_setup() used to run, which an sv_no_rpcbind serv no longer does.
 */
void nfsd_rpcb_unset_all(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(nfsd_rpcb_all); i++)
		nfs_svc_unregister(nfsd_rpcb_all[i].program,
				   nfsd_rpcb_all[i].version);
}

#ifdef HAVE_LIBTIRPC

/*
 * Map a transport name and address family to an rpcbind netid.
 *
 * Returns NULL for a transport that the kernel never registered. RDMA is
 * the case that matters: svc_register() is only reached from
 * svc_setup_socket(), so an RDMA listener was always absent from rpcbind.
 */
static const char *nfsd_rpcb_netid(const char *transport, int family)
{
	bool v6 = (family == AF_INET6);

	if (!strcmp(transport, "tcp"))
		return v6 ? "tcp6" : "tcp";
	if (!strcmp(transport, "udp"))
		return v6 ? "udp6" : "udp";
	return NULL;
}

/*
 * Build the address to register. The kernel registered the wildcard address
 * with the listener's port, not the address the listener is bound to, so
 * match that.
 */
static bool nfsd_rpcb_wildcard(const struct sockaddr_storage *ss,
			       struct sockaddr_storage *out, socklen_t *len)
{
	memset(out, 0, sizeof(*out));

	switch (ss->ss_family) {
	case AF_INET: {
		struct sockaddr_in *s4 = (struct sockaddr_in *)out;

		s4->sin_family = AF_INET;
		s4->sin_addr.s_addr = htonl(INADDR_ANY);
		s4->sin_port = ((const struct sockaddr_in *)ss)->sin_port;
		*len = sizeof(*s4);
		return true;
	}
	case AF_INET6: {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out;

		s6->sin6_family = AF_INET6;
		s6->sin6_addr = in6addr_any;
		s6->sin6_port = ((const struct sockaddr_in6 *)ss)->sin6_port;
		*len = sizeof(*s6);
		return true;
	}
	}
	return false;
}

static bool nfsd_rpcb_set_one(rpcprog_t program, rpcvers_t version,
			      const char *netid,
			      const struct sockaddr_storage *ss)
{
	struct sockaddr_storage wild;
	struct netconfig *nconf;
	struct netbuf nb;
	socklen_t len;
	bool ok;

	if (!nfsd_rpcb_wildcard(ss, &wild, &len))
		return false;

	nconf = getnetconfigent(netid);
	if (!nconf) {
		xlog(L_WARNING, "no netconfig entry for %s", netid);
		return false;
	}

	nb.buf = &wild;
	nb.len = len;
	nb.maxlen = len;

	ok = (rpcb_set(program, version, nconf, &nb) == TRUE);
	freenetconfigent(nconf);
	return ok;
}

/**
 * nfsd_rpcb_register - register the listeners the kernel reported
 * @listeners: listeners that came up, from the listener_set reply
 * @nlisteners: number of entries in @listeners
 * @progs: programs and versions the kernel would have registered
 * @nprogs: number of entries in @progs
 *
 * A failure is not fatal. NFSv4 does not need rpcbind, and a v2/v3 client
 * that already knows the port does not need it either, so an unadvertised
 * server is better than no server.
 */
void nfsd_rpcb_register(const struct server_socket *listeners, int nlisteners,
			const struct nfsd_rpcb_prog *progs, int nprogs)
{
	unsigned int failed = 0;
	int i, j, k;

	/*
	 * Clear first. rpcbind cannot express "drop one of two TCP ports",
	 * and the kernel no longer sweeps stale entries at serv creation.
	 */
	nfsd_rpcb_unset_all();

	for (i = 0; i < nlisteners; i++) {
		const struct server_socket *l = &listeners[i];
		const char *netid;
		bool dup = false;

		netid = nfsd_rpcb_netid(l->name, l->ss.ss_family);
		if (!netid)
			continue;

		/*
		 * The address registered is the wildcard, so two listeners
		 * that share a netid and port produce the same entry.
		 */
		for (k = 0; k < i; k++) {
			const struct server_socket *o = &listeners[k];
			const char *other;

			other = nfsd_rpcb_netid(o->name, o->ss.ss_family);
			if (other && !strcmp(other, netid) &&
			    nfs_get_port((const struct sockaddr *)&o->ss) ==
			    nfs_get_port((const struct sockaddr *)&l->ss)) {
				dup = true;
				break;
			}
		}
		if (dup)
			continue;

		for (j = 0; j < nprogs; j++) {
			const struct nfsd_rpcb_prog *p = &progs[j];

			/*
			 * NFSv4 needs congestion control, so the kernel
			 * never advertised it over UDP.
			 */
			if ((p->flags & NFSD_RPCBIND_FLAGS_NO_UDP) &&
			    !strncmp(netid, "udp", 3))
				continue;

			if (nfsd_rpcb_set_one(p->program, p->version, netid,
					      &l->ss))
				continue;

			xlog(L_WARNING,
			     "cannot register program %u version %u on %s port %u",
			     p->program, p->version, netid,
			     nfs_get_port((const struct sockaddr *)&l->ss));
			failed++;
		}
	}

	if (failed)
		xlog(L_WARNING,
		     "some rpcbind registrations failed. Clients that look up the server in rpcbind cannot find it.");
}

#else	/* !HAVE_LIBTIRPC */

/*
 * rpcb_set() and the netconfig database are TI-RPC only, so a build
 * without it cannot own the registration. userspace_rpcbind_supported()
 * answers false there and the kernel keeps doing the calls itself, which
 * leaves this unreachable.
 */
void nfsd_rpcb_register(const struct server_socket *UNUSED(listeners),
			int UNUSED(nlisteners),
			const struct nfsd_rpcb_prog *UNUSED(progs),
			int UNUSED(nprogs))
{
	xlog(L_WARNING, "built without TI-RPC: cannot register with rpcbind");
}

#endif	/* !HAVE_LIBTIRPC */

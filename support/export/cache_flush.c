/*
 * support/export/cache_flush.c
 *
 * Flush knfsd caches via netlink with /proc fallback.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#include "nfslib.h"
#include "xlog.h"

extern int no_netlink;

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>

#ifdef USE_SYSTEM_NFSD_NETLINK_H
#include <linux/nfsd_netlink.h>
#else
#include "nfsd_netlink.h"
#endif

#ifdef USE_SYSTEM_SUNRPC_NETLINK_H
#include <linux/sunrpc_netlink.h>
#else
#include "sunrpc_netlink.h"
#endif

static int nl_send_flush(struct nl_sock *sock, int family, int cmd)
{
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family,
			 0, 0, cmd, 0)) {
		nlmsg_free(msg);
		return -ENOMEM;
	}

	/* No mask attribute = flush all caches in this family */
	ret = nl_send_auto(sock, msg);
	if (ret >= 0)
		ret = nl_wait_for_ack(sock);
	nlmsg_free(msg);
	return ret;
}

static int cache_nl_flush(void)
{
	struct nl_sock *sock;
	int family, ret, val = 1;

	sock = nl_socket_alloc();
	if (!sock)
		return -1;

	if (genl_connect(sock)) {
		nl_socket_free(sock);
		return -1;
	}

	setsockopt(nl_socket_get_fd(sock), SOL_NETLINK, NETLINK_EXT_ACK,
		   &val, sizeof(val));

	/* Flush sunrpc caches first (dependency order) */
	family = genl_ctrl_resolve(sock, SUNRPC_FAMILY_NAME);
	if (family < 0) {
		xlog(D_NETLINK, "sunrpc genl family not found, "
		     "skipping netlink flush");
		nl_socket_free(sock);
		return -1;
	}

	ret = nl_send_flush(sock, family, SUNRPC_CMD_CACHE_FLUSH);
	if (ret < 0) {
		xlog(D_NETLINK, "sunrpc cache flush failed: %d", ret);
		nl_socket_free(sock);
		return -1;
	}

	/* Flush nfsd caches */
	family = genl_ctrl_resolve(sock, NFSD_FAMILY_NAME);
	if (family < 0) {
		xlog(D_NETLINK, "nfsd genl family not found, "
		     "skipping nfsd cache flush");
		nl_socket_free(sock);
		return 0;
	}

	ret = nl_send_flush(sock, family, NFSD_CMD_CACHE_FLUSH);
	nl_socket_free(sock);
	if (ret < 0) {
		xlog(D_NETLINK, "nfsd cache flush failed: %d", ret);
		return -1;
	}

	return 0;
}

static void cache_proc_flush(void)
{
	int c;
	char stime[32];
	char path[200];
	time_t now;
	/* Note: the order of these caches is important.
	 * They need to be flushed in dependency order. So
	 * a cache that references items in another cache,
	 * as nfsd.fh entries reference items in nfsd.export,
	 * must be flushed before the cache that it references.
	 */
	static char *cachelist[] = {
		"auth.unix.ip",
		"auth.unix.gid",
		"nfsd.fh",
		"nfsd.export",
		NULL
	};
	now = time(0);

	/* Since v4.16-rc2-3-g3b68e6ee3cbd the timestamp written is ignored.
	 * It is safest always to flush caches if there is any doubt.
	 * For earlier kernels, writing the next second from now is
	 * the best we can do.
	 */
	sprintf(stime, "%" PRId64 "\n", (int64_t)now+1);
	for (c=0; cachelist[c]; c++) {
		int fd;
		sprintf(path, "/proc/net/rpc/%s/flush", cachelist[c]);
		fd = open(path, O_RDWR);
		if (fd >= 0) {
			if (write(fd, stime, strlen(stime)) != (ssize_t)strlen(stime)) {
				xlog_warn("Writing to '%s' failed: errno %d (%s)",
				path, errno, strerror(errno));
			}
			close(fd);
		}
	}
}

void
cache_flush(void)
{
	if (!no_netlink && cache_nl_flush() == 0) {
		xlog(D_NETLINK, "cache flush via netlink succeeded");
		return;
	}
	/* Fallback: /proc path */
	cache_proc_flush();
}

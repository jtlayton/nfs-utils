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

#include "compat.h"

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

static int nl_policy_done_cb(struct nl_msg *UNUSED(msg), void *arg)
{
	int *done = arg;

	*done = 1;
	return NL_STOP;
}

static int nl_policy_error_cb(struct sockaddr_nl *UNUSED(nla),
			      struct nlmsgerr *UNUSED(nlerr), void *arg)
{
	int *done = arg;

	*done = 1;
	return NL_STOP;
}

/*
 * The dump covers SET_REQS's own policy and every nested policy it
 * references.  The svc_export attribute set is by far the largest of them,
 * so the highest attribute index seen is its maximum.
 */
static int nl_policy_valid_cb(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int *max_nlattr = arg;
	struct nlattr *attr, *pol, *a;
	int rem, prem, arem;

	nla_for_each_attr(attr, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), rem) {
		if (nla_type(attr) != CTRL_ATTR_POLICY)
			continue;
		nla_for_each_nested(pol, attr, prem) {
			nla_for_each_nested(a, pol, arem) {
				if (*max_nlattr < nla_type(a))
					*max_nlattr = nla_type(a);
			}
		}
	}
	return NL_OK;
}

/**
 * nfsd_export_iomode_supported - does the kernel take per-export I/O modes?
 *
 * The kernel refuses a whole svc_export entry over one attribute it does
 * not know, so ask which ones its SET_REQS policy accepts.
 *
 * Returns 1 if it accepts riomode/wiomode, 0 if not or if that cannot be
 * found out, or -1 if the nfsd netlink family is not registered, as when
 * nfsd is not loaded.
 */
int nfsd_export_iomode_supported(void)
{
	struct nl_msg *msg = NULL;
	struct nl_cb *cb = NULL;
	struct nl_sock *sock;
	int max_nlattr = 0;
	int supported = 0;
	int family, ret;
	int done = 0;

	sock = nl_socket_alloc();
	if (!sock)
		return 0;
	if (genl_connect(sock))
		goto out;

	family = genl_ctrl_resolve(sock, NFSD_FAMILY_NAME);
	if (family < 0) {
		supported = -1;
		goto out;
	}

	msg = nlmsg_alloc();
	if (!msg ||
	    !genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, GENL_ID_CTRL, 0,
			 NLM_F_DUMP, CTRL_CMD_GETPOLICY, 0) ||
	    nla_put_u16(msg, CTRL_ATTR_FAMILY_ID, family) < 0 ||
	    nla_put_u32(msg, CTRL_ATTR_OP, NFSD_CMD_SVC_EXPORT_SET_REQS) < 0)
		goto out;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto out;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl_policy_valid_cb,
		  &max_nlattr);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl_policy_done_cb, &done);
	nl_cb_err(cb, NL_CB_CUSTOM, nl_policy_error_cb, &done);

	ret = nl_send_auto(sock, msg);
	while (ret >= 0 && !done)
		ret = nl_recvmsgs(sock, cb);

	/* An error mid-dump leaves max_nlattr partial: trust only a full one */
	if (ret < 0)
		xlog(D_NETLINK, "nfsd policy query failed: %s",
		     nl_geterror(ret));
	else
		supported = max_nlattr >= NFSD_A_SVC_EXPORT_WRITE_IOMODE;
	xlog(D_NETLINK, "highest svc_export attribute is %d", max_nlattr);
out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	nl_socket_free(sock);
	return supported;
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
	no_netlink = 1;
	cache_proc_flush();
}

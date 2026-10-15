/*
 * support/export/export_policy.c
 *
 * Ask the kernel's nfsd netlink policy what a svc_export entry may carry.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "nfslib.h"
#include "exportfs.h"
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

#ifdef HAVE_GENL_POLICY_DUMP

/*
 * A SET_REQS policy dump covers the op's own policy, the svc_export policy
 * it nests, and the policies svc_export nests in turn.
 */
#define NL_POLICY_SLOTS	8

struct export_policy_dump {
	int		done;
	int		do_idx;		/* the op's own policy */
	/* per policy: */
	int		max_attr[NL_POLICY_SLOTS];
	int		reqs_idx[NL_POLICY_SLOTS];	/* REQUESTS nests this */
	uint64_t	flags_mask[NL_POLICY_SLOTS];	/* mask of FLAGS */
};

static int nl_policy_done_cb(struct nl_msg *UNUSED(msg), void *arg)
{
	struct export_policy_dump *d = arg;

	d->done = 1;
	return NL_STOP;
}

static int nl_policy_error_cb(struct sockaddr_nl *UNUSED(nla),
			      struct nlmsgerr *UNUSED(nlerr), void *arg)
{
	struct export_policy_dump *d = arg;

	d->done = 1;
	return NL_STOP;
}

/* Note what one NL_POLICY_TYPE_ATTR_* says about attribute @type of @idx */
static void nl_policy_type_attr(struct export_policy_dump *d, int idx,
				int type, struct nlattr *p)
{
	switch (nla_type(p)) {
	case NL_POLICY_TYPE_ATTR_POLICY_IDX:
		if (type == NFSD_A_SVC_EXPORT_REQS_REQUESTS &&
		    nla_len(p) >= (int)sizeof(uint32_t))
			d->reqs_idx[idx] = nla_get_u32(p);
		break;
	case NL_POLICY_TYPE_ATTR_MASK:
		if (type == NFSD_A_SVC_EXPORT_FLAGS &&
		    nla_len(p) >= (int)sizeof(uint64_t))
			d->flags_mask[idx] = nla_get_u64(p);
		break;
	}
}

static void nl_policy_op(struct export_policy_dump *d, struct nlattr *attr)
{
	struct nlattr *op, *a;
	int orem, arem;

	nla_for_each_nested(op, attr, orem) {
		nla_for_each_nested(a, op, arem) {
			if (nla_type(a) == CTRL_ATTR_POLICY_DO &&
			    nla_len(a) >= (int)sizeof(uint32_t))
				d->do_idx = nla_get_u32(a);
		}
	}
}

static void nl_policy_attrs(struct export_policy_dump *d, struct nlattr *attr)
{
	struct nlattr *pol, *a, *p;
	int prem, arem, rem;

	nla_for_each_nested(pol, attr, prem) {
		int idx = nla_type(pol);

		if (idx >= NL_POLICY_SLOTS)
			continue;
		nla_for_each_nested(a, pol, arem) {
			int type = nla_type(a);

			if (d->max_attr[idx] < type)
				d->max_attr[idx] = type;
			nla_for_each_nested(p, a, rem)
				nl_policy_type_attr(d, idx, type, p);
		}
	}
}

static int nl_policy_valid_cb(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attr;
	int rem;

	nla_for_each_attr(attr, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), rem) {
		switch (nla_type(attr)) {
		case CTRL_ATTR_OP_POLICY:
			nl_policy_op(arg, attr);
			break;
		case CTRL_ATTR_POLICY:
			nl_policy_attrs(arg, attr);
			break;
		}
	}
	return NL_OK;
}

/**
 * nfsd_export_policy_query - what does the kernel's svc_export policy accept?
 * @pol: filled in on success
 *
 * The kernel refuses a whole svc_export entry over one attribute or flag it
 * does not know, so ask its SET_REQS policy.  A successful answer is cached.
 *
 * Returns 0, -ENOENT if the nfsd netlink family is not registered, as when
 * nfsd is not loaded, or another negative errno if the policy could not be
 * read.
 */
int nfsd_export_policy_query(struct nfsd_export_policy *pol)
{
	static struct nfsd_export_policy cached;
	static bool have_cached;
	struct export_policy_dump d = { .do_idx = 0 };
	struct nl_msg *msg = NULL;
	struct nl_cb *cb = NULL;
	struct nl_sock *sock;
	int family, ret, svc, i;

	if (have_cached) {
		*pol = cached;
		return 0;
	}

	for (i = 0; i < NL_POLICY_SLOTS; i++)
		d.reqs_idx[i] = -1;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	ret = -ECONNREFUSED;
	if (genl_connect(sock))
		goto out;

	ret = -ENOENT;
	family = genl_ctrl_resolve(sock, NFSD_FAMILY_NAME);
	if (family < 0)
		goto out;

	ret = -ENOMEM;
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

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl_policy_valid_cb, &d);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl_policy_done_cb, &d);
	nl_cb_err(cb, NL_CB_CUSTOM, nl_policy_error_cb, &d);

	ret = nl_send_auto(sock, msg);
	while (ret >= 0 && !d.done)
		ret = nl_recvmsgs(sock, cb);

	/* An error mid-dump leaves the tables partial: trust only a full one */
	if (ret < 0) {
		xlog(D_NETLINK, "nfsd policy query failed: %s",
		     nl_geterror(ret));
		ret = -EPROTO;
		goto out;
	}

	svc = -1;
	if (d.do_idx >= 0 && d.do_idx < NL_POLICY_SLOTS)
		svc = d.reqs_idx[d.do_idx];
	if (svc < 0 || svc >= NL_POLICY_SLOTS) {
		xlog(D_NETLINK, "nfsd policy query: no svc_export policy");
		ret = -EPROTO;
		goto out;
	}

	cached.flags = d.flags_mask[svc];
	/*
	 * The auth-flavor FLAGS mask is the full set too, so the policy
	 * cannot say which flags may vary per flavor.  These are the same on
	 * every kernel with the netlink export interface.
	 */
	cached.secinfo_flags = NFSEXP_SECINFO_FLAGS;
	cached.max_attr = d.max_attr[svc];
	have_cached = true;
	xlog(D_NETLINK, "svc_export policy: max attribute %d, flags 0x%x",
	     cached.max_attr, cached.flags);
	*pol = cached;
	ret = 0;
out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	nl_socket_free(sock);
	return ret;
}

#else /* HAVE_GENL_POLICY_DUMP */

int nfsd_export_policy_query(struct nfsd_export_policy *UNUSED(pol))
{
	return -EOPNOTSUPP;
}

#endif /* HAVE_GENL_POLICY_DUMP */

/**
 * nfsd_export_iomode_supported - does the kernel take per-export I/O modes?
 *
 * A kernel without them refuses any svc_export entry that carries one.
 *
 * Returns 1 if it accepts riomode/wiomode, 0 if not or if that cannot be
 * found out, or -1 if the nfsd netlink family is not registered, as when
 * nfsd is not loaded.
 */
int nfsd_export_iomode_supported(void)
{
	struct nfsd_export_policy pol;
	int ret;

	ret = nfsd_export_policy_query(&pol);
	if (ret == -ENOENT)
		return -1;
	if (ret < 0)
		return 0;
	return pol.max_attr >= NFSD_A_SVC_EXPORT_WRITE_IOMODE;
}

/**
 * nfsd_nl_load_export_features - learn the kernel's export flags over netlink
 *
 * The svc_export policy masks NFSD_A_SVC_EXPORT_FLAGS to the flags the kernel
 * knows, which is what /proc/fs/nfsd/export_features reports.  Hand that to
 * get_export_features(), so that it need not read /proc.  If netlink cannot
 * say, get_export_features() falls back to /proc as before.
 */
void nfsd_nl_load_export_features(void)
{
	struct nfsd_export_policy pol;

	if (no_netlink || nfsd_export_policy_query(&pol) < 0 || !pol.flags)
		return;

	set_export_features(&pol);
}

/**
 * @file support/junction/export-cache.c
 * @brief Try to flush NFSD's exports cache
 */

/*
 * Copyright 2011, 2018 Oracle.  All rights reserved.
 *
 * This file is part of nfs-utils.
 *
 * nfs-utils is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2.0 as
 * published by the Free Software Foundation.
 *
 * nfs-utils is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2.0 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2.0 along with nfs-utils.  If not, see:
 *
 *	http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 */

#include <stdbool.h>

#include "junction.h"
#include "nfslib.h"
#include "xlog.h"

/**
 * Flush the kernel NFSD's exports cache
 *
 * cache_flush() uses netlink when the kernel offers it, and falls back
 * to the /proc flush files otherwise.
 *
 * @return a FedFsStatus code
 */
FedFsStatus
junction_flush_exports_cache(void)
{
	xlog(D_CALL, "%s: Flushing NFSD caches...", __func__);
	cache_flush();
	return FEDFS_OK;
}

#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Recommend NFSD read and write IO modes (read_io= and write_io=) for an
export, based on page cache and memory reclaim metrics sampled while
clients use the export.

See Documentation/filesystems/nfs/nfsd-io-modes.rst in the kernel tree.
"""

import argparse
import ctypes
import errno
import json
import os
import platform
import re
import struct
import sys
import time

EXPORT_STATS = '/proc/fs/nfsd/export_stats'
EXPORT_CONTENT = '/proc/net/rpc/nfsd.export/content'
ETAB = '/var/lib/nfs/etab'
NFSD_STATS = '/proc/net/rpc/nfsd'
DEBUGFS_NFSD = '/sys/kernel/debug/nfsd'
DEBUGFS_BDI = '/sys/kernel/debug/bdi'
CGROUP_ROOT = '/sys/fs/cgroup'

IOMODES = ['buffered', 'dontcache', 'direct']
COUNTERS = ('io_read', 'io_write', 'io_read_storage')

RWF_DONTCACHE = 0x80
AT_FDCWD = -100
STATX_DIOALIGN = 0x2000
STATX_DIO_READ_ALIGN = 0x20000

# Heuristic thresholds. These are starting points, not tuned values.
# They are ratios, or relative to the traffic of the export, the limits
# of the kernel, or the storage, so that they do not depend on the size
# of the server.
MIN_IO_BYTES = 64 << 20          # less traffic than this is not conclusive
MISS_LOW = 0.5                   # below: page cache supplies most READ data
MISS_HIGH = 0.8                  # above: storage supplies most READ data
EVICT_MISS = 0.05                # below: no READ data of the export is evicted
READAHEAD_MISS = 1.05            # above: readahead reads unrequested data
RECLAIM_TRAFFIC = 0.25           # bytes reclaimed / export storage traffic
REFAULT_FRAC = 0.1               # refaults / pages reclaimed
DIRECT_FRAC = 0.1                # direct reclaim / all reclaim
PSI_SOME_PCT = 1.0
PSI_FULL_PCT = 1.0
RECLAIM_CPU_PCT = 10.0           # busiest kswapd or kcompactd, % of one CPU
DIRTY_BG_FRAC = 0.5              # (Dirty + Writeback) / background threshold
FREE_HIGH = 4                    # above: free memory / high watermarks
LARGE_IO = 64 << 10              # average READ/WRITE size for direct IO
LARGE_WRITE_PAGES = 3            # average WRITE size for direct IO, in pages
MAX_IO_OPT = 16 << 20            # larger optimal_io_size values are not real
FILE_SCAN = 10000                # files to examine for --sample-files
XDR_ALIGN = 4                    # alignment of WRITE data received over TCP

# Filesystems that read storage from threads other than the NFSD thread.
# io_read_storage does not count these reads.
UNCHARGED_FS = ('fuse', 'fuseblk', 'zfs')

PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')

# Indexes of READ (and NFSv4.2 READ_PLUS) and WRITE in the
# /proc/net/rpc/nfsd procN lines
PROC_READ_WRITE = {'proc2': ((6,), (8,)), 'proc3': ((6,), (7,)),
                   'proc4ops': ((25, 68), (38,))}

_octal_escape = re.compile(r'\\([0-7]{3})')


def unescape(s):
    return _octal_escape.sub(lambda m: chr(int(m.group(1), 8)), s)


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def read_export_stats():
    """Return {(path, domain): {'start': start_time, counter: value}}."""
    text = read_file(EXPORT_STATS)
    if text is None:
        sys.exit('cannot read %s: is nfsd running?' % EXPORT_STATS)
    stats = {}
    key = None
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        if not line.startswith('\t'):
            fields = line.split('\t')
            key = (unescape(fields[0]), unescape(fields[1]))
            stats[key] = {'start': int(fields[2]), 'io_read': 0, 'io_write': 0}
        elif key is not None:
            name, _, val = line.strip().partition(':')
            stats[key][name] = int(val)
    return stats


def read_etab():
    """Return {path: [options of each client]} from the exportfs table.

    The kernel adds an export to export_stats only when a client uses it.
    """
    exports = {}
    for line in (read_file(ETAB) or '').splitlines():
        fields = line.split('\t')
        if len(fields) < 2:
            continue
        opts = fields[1].partition('(')[2].rstrip(')')
        exports.setdefault(unescape(fields[0]), []).append(opts)
    return exports


def read_export_modes(path, etab):
    """Return the per-export (read_io, write_io) of path, None if unset."""
    opts = []
    for line in (read_file(EXPORT_CONTENT) or '').splitlines():
        if line.startswith('#') or '\t' not in line:
            continue
        epath, _, rest = line.partition('\t')
        if unescape(epath) == path:
            opts.append(rest)
    if not opts:
        # No export cache entry yet. Use the settings that mountd sends.
        opts = etab.get(path, [])
    rmode = wmode = None
    for o in opts:
        m = re.search(r'read_io=(\w+)', o)
        if m:
            rmode = m.group(1)
        m = re.search(r'write_io=(\w+)', o)
        if m:
            wmode = m.group(1)
    return rmode, wmode


def read_global_mode(name):
    val = read_file(os.path.join(DEBUGFS_NFSD, name))
    if val is None:
        return None
    try:
        return IOMODES[int(val)]
    except (ValueError, IndexError):
        return None


def read_nfsd_ops():
    """Return global NFSD READ/WRITE operation counts and bytes."""
    text = read_file(NFSD_STATS) or ''
    out = {'reads': 0, 'writes': 0, 'read_bytes': 0, 'write_bytes': 0}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == 'io':
            out['read_bytes'] = int(fields[1])
            out['write_bytes'] = int(fields[2])
        elif fields[0] in PROC_READ_WRITE:
            counts = [int(x) for x in fields[2:]]
            rd, wr = PROC_READ_WRITE[fields[0]]
            out['reads'] += sum(counts[i] for i in rd if i < len(counts))
            out['writes'] += sum(counts[i] for i in wr if i < len(counts))
    return out


def read_kv(path, sep=None):
    out = {}
    for line in (read_file(path) or '').splitlines():
        fields = line.replace(':', ' ').split() if sep is None else line.split(sep)
        if len(fields) >= 2:
            try:
                out[fields[0]] = int(fields[1])
            except ValueError:
                pass
    return out


def read_psi(path='/proc/pressure/memory'):
    """Return {'some': total_usec, 'full': total_usec}."""
    out = {}
    for line in (read_file(path) or '').splitlines():
        fields = line.split()
        for f in fields[1:]:
            if f.startswith('total='):
                out[fields[0]] = int(f[6:])
    return out


def read_int(path):
    try:
        return int(read_file(path))
    except (TypeError, ValueError):
        return None


def read_reclaim_threads():
    """Return {pid: (name, CPU ticks)} of the kswapd and kcompactd threads.

    There is one of each for each NUMA node.
    """
    out = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        comm = read_file('/proc/%s/comm' % pid)
        if not comm or not comm.startswith(('kswapd', 'kcompactd')):
            continue
        stat = read_file('/proc/%s/stat' % pid)
        if stat:
            fields = stat.rpartition(')')[2].split()
            out[pid] = (comm.strip(), int(fields[11]) + int(fields[12]))
    return out


def read_free_memory():
    """Return (free pages, sum of the high watermarks) of all zones.

    kswapd reclaims until free memory reaches the high watermarks. Free
    memory far above them shows that the page cache has not filled yet.
    """
    free = high = 0
    for line in (read_file('/proc/zoneinfo') or '').splitlines():
        fields = line.split()
        if fields[:2] == ['pages', 'free']:
            free += int(fields[2])
        elif fields[:1] == ['high'] and len(fields) == 2:
            high += int(fields[1])
    return free, high


def read_memcg_limits():
    """Return {cgroup: (limit events, pgsteal_direct, refaults, psi)}.

    A cgroup at its memory.high or memory.max reclaims its own pages. That
    reclaim adds to pgsteal_direct and workingset_refault_file in
    /proc/vmstat, and its tasks stall in /proc/pressure/memory, but it is
    not system memory pressure. memory.stat and memory.pressure values
    include descendants. memory.events.local counts only limits of the
    cgroup itself.
    """
    out = {}
    stack = [CGROUP_ROOT]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                stack.append(e.path)
        if d == CGROUP_ROOT:
            continue
        ev = read_kv(os.path.join(d, 'memory.events.local'))
        if not ev:
            continue
        st = read_kv(os.path.join(d, 'memory.stat'), sep=' ')
        out[d] = (ev.get('high', 0) + ev.get('max', 0),
                  st.get('pgsteal_direct', 0),
                  st.get('workingset_refault_file', 0),
                  read_psi(os.path.join(d, 'memory.pressure')))
    return out


def memcg_limit_delta(a, b):
    """Return the reclaim and stalls of cgroups at their memory limit.

    Count each cgroup that reached its limit during the interval, unless
    an ancestor did too: the ancestor's statistics already include it.
    Reclaim adds up across cgroups. Stall time does not, because the
    stalls of different cgroups can overlap, so return the largest.
    """
    hit = sorted(d for d, v in b.items() if d in a and v[0] > a[d][0])
    top = [d for d in hit
           if not any(d.startswith(p + '/') for p in hit)]
    out = {'reclaimed': sum(max(b[d][1] - a[d][1], 0) for d in top),
           'refault': sum(max(b[d][2] - a[d][2], 0) for d in top),
           'cgroups': [os.path.relpath(d, CGROUP_ROOT) for d in top]}
    for kind in ('some', 'full'):
        out['psi_' + kind] = max([b[d][3].get(kind, 0) -
                                  a[d][3].get(kind, 0) for d in top] or [0])
    return out


def find_mount(path, st_dev):
    """Return (fstype, source) of the filesystem that holds path."""
    devstr = '%d:%d' % (os.major(st_dev), os.minor(st_dev))
    best = None
    for line in (read_file('/proc/self/mountinfo') or '').splitlines():
        pre, _, post = line.partition(' - ')
        pre, post = pre.split(), post.split()
        fs = (post[0], unescape(post[1]))
        if pre[2] == devstr:
            return fs
        # btrfs subvolumes do not match the device in mountinfo
        mnt = unescape(pre[4])
        if (path == mnt or path.startswith(mnt.rstrip('/') + '/')) and \
           (best is None or len(mnt) >= len(best[0])):
            best = (mnt, fs)
    return best[1] if best else (None, None)


def find_block_stat(st_dev, source):
    """Return the sysfs stat file of the block device of a filesystem."""
    path = '/sys/dev/block/%d:%d/stat' % (os.major(st_dev), os.minor(st_dev))
    if os.path.exists(path):
        return path
    # btrfs and others report an anonymous st_dev. Use the mount source.
    if source and source.startswith('/dev/'):
        try:
            rdev = os.stat(source).st_rdev
        except OSError:
            return None
        path = '/sys/dev/block/%d:%d/stat' % (os.major(rdev), os.minor(rdev))
        if os.path.exists(path):
            return path
    return None


def find_queue(block_stat):
    """Return the sysfs queue directory of the block device of block_stat.

    A partition has no queue directory. Use the queue of its disk.
    """
    if block_stat is None:
        return None
    d = os.path.realpath(os.path.dirname(block_stat))
    for q in (os.path.join(d, 'queue'), os.path.join(d, '..', 'queue')):
        if os.path.isdir(q):
            return os.path.realpath(q)
    return None


def read_block(path):
    """Return (read_bytes, write_bytes) of a block device."""
    if path is None:
        return None
    fields = (read_file(path) or '').split()
    if len(fields) < 7:
        return None
    return int(fields[2]) * 512, int(fields[6]) * 512


def find_bdi(st_dev, fstype, source):
    """Return (name, stats path) of the backing device of a filesystem.

    The dirty data of a filesystem is accounted to the backing device
    (bdi) of its superblock. A filesystem on a whole disk or a device
    mapper device uses the bdi of that device. A filesystem on a
    partition uses the bdi of the disk. btrfs and filesystems without
    a block device (NFS, FUSE) have their own bdi.
    """
    dev = '%d:%d' % (os.major(st_dev), os.minor(st_dev))
    names = []
    if fstype == 'btrfs' and source and source.startswith('/dev/'):
        part = os.path.basename(os.path.realpath(source))
        for d in os.listdir('/sys/fs/btrfs') \
                if os.path.isdir('/sys/fs/btrfs') else []:
            if os.path.exists(os.path.join('/sys/fs/btrfs', d, 'devices',
                                           part)):
                try:
                    names.append(os.path.basename(os.readlink(
                        os.path.join('/sys/fs/btrfs', d, 'bdi'))))
                except OSError:
                    pass
    sysdev = '/sys/dev/block/' + dev
    if os.path.exists(os.path.join(sysdev, 'partition')):
        parent = read_file(os.path.join(os.path.realpath(sysdev), '..',
                                        'dev'))
        if parent:
            names.append(parent.strip())
    names.append(dev)
    for n in names:
        path = os.path.join(DEBUGFS_BDI, n, 'stats')
        if os.path.exists(path):
            return n, path
    return None, None


def read_dirty(ctx):
    """Return (Dirty + Writeback, background writeback threshold) in kB.

    The dirty data is that of the export's bdi if possible. The threshold
    is that of the system, from vm.dirty_background_ratio or
    vm.dirty_background_bytes. Servers with much memory often set the
    second, so the threshold is not a fixed fraction of memory.
    """
    if ctx['bdi_stats']:
        kv = read_kv(ctx['bdi_stats'])
        if 'BdiReclaimable' in kv:
            return (kv['BdiReclaimable'] + kv.get('BdiWriteback', 0),
                    kv.get('BackgroundThresh', 0))
    meminfo = read_kv('/proc/meminfo')
    vmstat = read_kv('/proc/vmstat', sep=' ')
    return (meminfo.get('Dirty', 0) + meminfo.get('Writeback', 0),
            vmstat.get('nr_dirty_background_threshold', 0) *
            PAGE_SIZE // 1024)


class Cachestat:
    """Wrapper for cachestat(2), available in Linux 6.5 and later."""

    class Range(ctypes.Structure):
        _fields_ = [('off', ctypes.c_uint64), ('len', ctypes.c_uint64)]

    FIELDS = ('nr_cache', 'nr_dirty', 'nr_writeback',
              'nr_evicted', 'nr_recently_evicted')

    class Stat(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in
                    ('nr_cache', 'nr_dirty', 'nr_writeback',
                     'nr_evicted', 'nr_recently_evicted')]

    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.nr = 561 if platform.machine().startswith('alpha') else 451

    def __call__(self, path):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOATIME)
        except OSError:
            try:
                fd = os.open(path, os.O_RDONLY)
            except OSError:
                return None
        try:
            rng = self.Range(0, 0)
            cs = self.Stat()
            if self.libc.syscall(self.nr, fd, ctypes.byref(rng),
                                 ctypes.byref(cs), 0) != 0:
                return None
            return {n: getattr(cs, n) for n in self.FIELDS}
        finally:
            os.close(fd)


def probe_dontcache(files):
    """Return True if the filesystem accepts RWF_DONTCACHE, None if unknown.

    NFSD silently uses buffered IO instead of dontcache when the
    filesystem does not set FOP_DONTCACHE.
    """
    for path in files:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            continue
        try:
            os.preadv(fd, [bytearray(1)], 0, RWF_DONTCACHE)
            return True
        except OSError as e:
            if e.errno in (errno.EOPNOTSUPP, errno.EINVAL):
                return False
        finally:
            os.close(fd)
    return None


def probe_direct(files):
    """Return (read_ok, write_ok, mem_align), Nones if unknown.

    NFSD uses the STATX_DIOALIGN and STATX_DIO_READ_ALIGN values of the
    file. Without them, NFSD does not use direct IO. A direct READ or
    WRITE then uses dontcache if possible, else buffered IO.
    """
    try:
        statx = ctypes.CDLL(None, use_errno=True).statx
    except AttributeError:
        return None, None, None
    for path in files:
        buf = ctypes.create_string_buffer(0x100)
        if statx(AT_FDCWD, path.encode(), 0,
                 STATX_DIOALIGN | STATX_DIO_READ_ALIGN, buf) != 0:
            continue
        mask, = struct.unpack_from('I', buf, 0x00)
        mem_align, offset_align = struct.unpack_from('II', buf, 0x98)
        read_align, = struct.unpack_from('I', buf, 0xb4)
        if not mask & STATX_DIOALIGN:
            mem_align = offset_align = 0
        if not mask & STATX_DIO_READ_ALIGN:
            read_align = offset_align
        return bool(read_align), bool(mem_align and offset_align), mem_align
    return None, None, None


def rdma_listener():
    """Return True if NFSD listens for RPC-over-RDMA connections."""
    ports = read_file('/proc/fs/nfsd/portlist') or ''
    return any(line.split()[:1] == ['rdma'] for line in ports.splitlines())


def pick_files(root, count, budget):
    """Return the largest regular files under root, on the same filesystem.

    Examine at most budget files.
    """
    dev = os.stat(root).st_dev
    found = []
    stack = [root]
    while stack and budget > 0:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if st.st_dev != dev:
                continue
            if e.is_dir(follow_symlinks=False):
                stack.append(e.path)
            elif e.is_file(follow_symlinks=False) and st.st_size:
                found.append((st.st_size, e.path))
                budget -= 1
    found.sort(reverse=True)
    return [p for _, p in found[:count]]


def sample(ctx):
    s = {
        'time': time.monotonic(),
        'exports': read_export_stats(),
        'nfsd': read_nfsd_ops(),
        'vmstat': read_kv('/proc/vmstat', sep=' '),
        'psi': read_psi(),
        'reclaim': read_reclaim_threads(),
        'memcg': read_memcg_limits(),
        'block': read_block(ctx['block_stat']),
    }
    if ctx['files']:
        cs = [ctx['cachestat'](p) for p in ctx['files']]
        s['cachestat'] = [c for c in cs if c is not None]
    return s


def measure(ctx, interval):
    """Return the samples at the start and end of the interval, and the
    dirty data and threshold of each second.

    The amount of dirty data changes quickly. Two values are not enough.
    """
    a = sample(ctx)
    dirty = [read_dirty(ctx)]
    end = a['time'] + interval
    while True:
        left = end - time.monotonic()
        if left <= 0:
            break
        time.sleep(min(left, 1.0))
        dirty.append(read_dirty(ctx))
    return a, sample(ctx), dirty


def export_delta(a, b, paths):
    """Sum the counter deltas of all entries for paths.

    The kernel keeps the counters of an export across export cache
    updates, but does not list an entry while it is out of the cache.
    An entry that is new in b, or whose start time changed, counts only
    if its counters started during the interval. Otherwise its traffic
    in the interval is not known. The start time is CLOCK_MONOTONIC
    seconds, the clock of time.monotonic().

    An entry that is in a but not in b left the cache during the
    interval, for example by a cache flush. Its traffic after a is not
    known either.

    Returns (deltas, incomplete). A counter that an entry does not
    report is None in deltas.
    """
    out = dict.fromkeys(COUNTERS, 0)
    incomplete = any(key[0] in paths and key not in b['exports']
                     for key in a['exports'])
    t0 = int(a['time'])
    for key, nv in b['exports'].items():
        if key[0] not in paths:
            continue
        ov = a['exports'].get(key)
        if ov is not None and ov['start'] == nv['start']:
            base = ov
        elif nv['start'] >= t0:
            base = {}
        else:
            incomplete = True
            continue
        for c in COUNTERS:
            if out[c] is None:
                continue
            if c not in nv or (base and c not in base):
                out[c] = None
            else:
                out[c] += nv[c] - base.get(c, 0)
    return out, incomplete


def analyze(ctx, a, b, dirty):
    dt = b['time'] - a['time']
    va, vb = a['vmstat'], b['vmstat']

    def dv(name):
        return vb.get(name, 0) - va.get(name, 0)

    m = {'interval': dt}
    d, m['incomplete'] = export_delta(a, b, {ctx['path']})
    m['io_read'], m['io_write'] = d['io_read'], d['io_write']
    fs, fs_incomplete = export_delta(a, b, ctx['fs_exports'])
    m['fs_io_read'] = fs['io_read']

    # io_read_storage is exact for the export, if the NFSD thread submits
    # the storage reads. Block device reads also count other exports and
    # local applications on the device.
    m['device_read'] = m['device_miss_ratio'] = None
    if a['block'] and b['block']:
        m['device_read'] = b['block'][0] - a['block'][0]
        if fs['io_read']:
            m['device_miss_ratio'] = m['device_read'] / fs['io_read']
    storage = None if ctx['uncharged'] else d['io_read_storage']
    m['storage_read'] = m['miss_ratio'] = m['miss_source'] = None
    if storage is not None:
        if d['io_read']:
            m['storage_read'] = storage
            m['miss_ratio'] = storage / d['io_read']
            m['miss_source'] = 'export'
    elif m['device_miss_ratio'] is not None:
        m['storage_read'] = m['device_read']
        m['miss_ratio'] = m['device_miss_ratio']
        m['miss_source'] = 'device'
        m['incomplete'] = m['incomplete'] or fs_incomplete

    na, nb = a['nfsd'], b['nfsd']
    reads = nb['reads'] - na['reads']
    writes = nb['writes'] - na['writes']
    m['avg_read'] = (nb['read_bytes'] - na['read_bytes']) // reads if reads else None
    m['avg_write'] = (nb['write_bytes'] - na['write_bytes']) // writes if writes else None

    # Reclaim by cgroups at their memory limit is not system memory
    # pressure. Do not count it.
    lim = memcg_limit_delta(a['memcg'], b['memcg'])
    m['memcg_reclaimed'] = lim['reclaimed']
    m['memcg_refault'] = lim['refault']
    m['memcg_cgroups'] = lim['cgroups']
    m['reclaimed_direct'] = max(dv('pgsteal_direct') - m['memcg_reclaimed'], 0)
    m['reclaimed'] = dv('pgsteal_kswapd') + m['reclaimed_direct']
    m['refault'] = max(dv('workingset_refault_file') - m['memcg_refault'], 0)
    m['activate'] = dv('workingset_activate_file')
    m['allocstall'] = sum(vb[k] - va.get(k, 0) for k in vb
                          if k.startswith('allocstall'))
    m['pgscan_direct'] = dv('pgscan_direct')
    m['compact_stall'] = dv('compact_stall')
    m['refault_frac'] = m['refault'] / m['reclaimed'] if m['reclaimed'] else 0
    # The share of reclaim that allocating tasks do themselves. It
    # increases when kswapd cannot reclaim fast enough. A count of stalls
    # increases with the number of threads, and thus with server size.
    m['direct_frac'] = m['reclaimed_direct'] / m['reclaimed'] \
        if m['reclaimed'] else None

    # Compare reclaim with the data that the export moves into the page
    # cache, not with the memory size. Reclaim can go only as fast as
    # storage fills the page cache, and a server with much memory and
    # slow storage never reclaims a large fraction of its memory.
    est_read = m['io_read'] * m['miss_ratio'] \
        if m['miss_ratio'] is not None else m['io_read']
    m['traffic'] = est_read + m['io_write']
    m['reclaim_traffic'] = m['reclaimed'] * PAGE_SIZE / m['traffic'] \
        if m['traffic'] else None

    # Stalls of tasks in cgroups at their memory limit are not system
    # memory pressure either. Without them, at least the rest remains.
    for kind in ('some', 'full'):
        m['memcg_psi_' + kind] = lim['psi_' + kind] / (dt * 1e4)
        if kind in a['psi'] and kind in b['psi']:
            m['psi_' + kind] = max(b['psi'][kind] - a['psi'][kind] -
                                   lim['psi_' + kind], 0) / (dt * 1e4)
        else:
            m['psi_' + kind] = None

    # Use the busiest thread. The sum of all of them increases with the
    # number of NUMA nodes, but each node has its own kswapd.
    ra, rb = a['reclaim'], b['reclaim']
    ticks, m['reclaim_thread'] = max(((rb[p][1] - ra[p][1], rb[p][0])
                                      for p in rb if p in ra),
                                     default=(0, None))
    if not ticks:
        m['reclaim_thread'] = None
    m['reclaim_cpu'] = ticks * 100.0 / (os.sysconf('SC_CLK_TCK') * dt)

    m['dirty_kb'] = sum(v for v, _ in dirty) // len(dirty)
    m['dirty_bg_kb'] = sum(t for _, t in dirty) // len(dirty)
    m['dirty_bg_frac'] = m['dirty_kb'] / m['dirty_bg_kb'] \
        if m['dirty_bg_kb'] else 0
    m['dirty_source'] = ctx['bdi'] or 'all devices'

    # A server with much memory can take many minutes to fill its page
    # cache. Until then, there is no reclaim. While there is reclaim, free
    # memory can be far above the watermarks (kswapd reclaims past them,
    # and a NUMA node can be full while others are not), so reclaim also
    # shows a full page cache.
    free, high = read_free_memory()
    m['free_kb'] = free * PAGE_SIZE // 1024
    m['cache_full'] = bool(m['reclaimed']) or not high or \
        free <= FREE_HIGH * high
    m['fill_minutes'] = free * PAGE_SIZE * dt / (m['traffic'] * 60) \
        if m['traffic'] else None

    if 'cachestat' in b:
        csa = {k: sum(c[k] for c in a['cachestat']) for k in Cachestat.FIELDS}
        csb = {k: sum(c[k] for c in b['cachestat']) for k in Cachestat.FIELDS}
        m['cachestat'] = {'files': len(b['cachestat']), **csb,
                          'recently_evicted_delta':
                              csb['nr_recently_evicted'] - csa['nr_recently_evicted']}
    return m


def recommend(ctx, m):
    """Return (read_io, read_reasons, write_io, write_reasons)."""
    pressure = (m['reclaim_traffic'] or 0) > RECLAIM_TRAFFIC or \
        (m['psi_some'] or 0) > PSI_SOME_PCT
    costly = (m['psi_full'] or 0) > PSI_FULL_PCT or \
        m['reclaim_cpu'] > RECLAIM_CPU_PCT or \
        (pressure and (m['direct_frac'] or 0) > DIRECT_FRAC)
    dontcache_ok = ctx['dontcache'] is not False
    fsname = ctx['fstype'] or 'This filesystem'

    def uncached(avg, large_min, why, direct, direct_why=None):
        large = avg is not None and avg >= large_min
        if direct is None or ctx['dontcache'] is None:
            why = why + ['IO mode support was not verified. No readable '
                         'file was found in the export.']
        if direct is not False and ctx['rotational']:
            direct = False
            direct_why = ('the storage is rotational. Direct IO gives up '
                          'the readahead and writeback of the page cache, '
                          'which make fewer and larger requests.')
        direct_ok = direct is not False
        if costly and large and direct_ok:
            return 'direct', why + ['Page reclaim is costly and the average '
                                    'IO size is large.']
        if costly and large and direct_why:
            # Direct IO would help, but NFSD cannot use it here
            why = why + ['Page reclaim is costly and the average IO size '
                         'is large, but ' + direct_why]
        if dontcache_ok:
            return 'dontcache', why
        # Direct IO helps over buffered IO only if page reclaim is costly
        if not direct_ok and direct_why:
            return 'buffered', why + ['%s does not support dontcache.' %
                                      fsname]
        if not direct_ok:
            return 'buffered', why + ['%s supports neither dontcache nor '
                                      'direct IO. NFSD uses buffered IO for '
                                      'all modes.' % fsname]
        if not large:
            return 'buffered', why + ['%s does not support dontcache, and '
                                      'the average IO size is small for '
                                      'direct IO.' % fsname]
        return 'buffered', why + ['%s does not support dontcache, and page '
                                  'reclaim is not costly enough for direct '
                                  'IO.' % fsname]

    def unfilled():
        if pressure or m['cache_full']:
            return []
        why = ['Free memory is far above the reclaim watermarks, so the '
               'page cache has not filled yet.']
        if ctx['fs_used'] is not None and \
                ctx['fs_used'] <= m['free_kb'] * 1024:
            why.append('All data on the filesystem of the export (%s) fits '
                       'in free memory, so READs of this export alone '
                       'cannot fill it.' % fmt_bytes(ctx['fs_used']))
            return why
        why.append('When it fills, there can be page reclaim, and the '
                   'recommendation can change.')
        if m['fill_minutes'] is not None:
            why.append('At the current storage traffic of the export, free '
                       'memory fills in about %.0f minutes. Run again after '
                       'that, or with a longer interval.' % m['fill_minutes'])
        return why

    def current_mode(opt, knob, mode, src):
        if src == 'export':
            return 'The export uses %s=%s.' % (opt, mode)
        return 'The export has no %s= setting, and the global %s setting ' \
               'is %s.' % (opt, knob, mode)

    def eviction():
        why = []
        if m.get('cachestat', {}).get('recently_evicted_delta', 0) > 0:
            why.append('Page reclaim evicts data of this export.')
        elif pressure and m['refault_frac'] > REFAULT_FRAC and \
                m['miss_ratio'] > EVICT_MISS:
            # System-wide refaults matter only if storage supplies some
            # READ data of this export
            why.append('Page reclaim evicts file data that is then read '
                       'again.')
        if why:
            why.append('Other exports with read-once data can use dontcache '
                       'or direct IO to give more page cache to this one.')
        return why

    readahead = []
    if m['miss_ratio'] is not None and m['miss_ratio'] > READAHEAD_MISS:
        readahead = ['Storage read more data than NFSD returned. Readahead '
                     'reads data that clients do not request, for example '
                     'with small random READs.']

    # READ
    rwhy = []
    if ctx['cur_read'] not in ('buffered', None):
        rmode = None
        rwhy.append(current_mode('read_io', 'io_cache_read', ctx['cur_read'],
                                 ctx['read_src']) +
                    ' The miss ratio is not meaningful. Set '
                    'read_io=buffered and run again.')
    elif m['io_read'] < MIN_IO_BYTES:
        rmode = None
        rwhy.append('Not enough READ traffic in the interval.')
    elif m['miss_ratio'] is None and ctx['uncharged']:
        rmode = None
        rwhy.append('%s reads storage from its own threads, which '
                    'io_read_storage does not count, and has no block '
                    'device statistics. The miss ratio is not available.' %
                    fsname)
    elif m['miss_ratio'] is None:
        rmode = None
        rwhy.append('No block device statistics for this filesystem. '
                    'The miss ratio is not available.')
    elif m['miss_ratio'] < MISS_LOW:
        rmode = 'buffered'
        rwhy.append('The page cache supplies most READ data.')
        if m['miss_source'] == 'export' and m['miss_ratio'] < EVICT_MISS and \
                (m['device_miss_ratio'] or 0) > MISS_LOW:
            rwhy.append('But the block device read %s while NFSD read %s. '
                        'io_read_storage counts only the storage reads that '
                        'NFSD threads submit. If %s reads storage from other '
                        'threads, the miss ratio is too low.' %
                        (fmt_bytes(m['device_read']),
                         fmt_bytes(m['fs_io_read']), fsname))
        rwhy += eviction()
    elif m['miss_ratio'] < MISS_HIGH:
        rmode = 'buffered'
        rwhy.append('The page cache supplies part of the READ data.')
        rwhy += eviction()
    elif not pressure and ctx['cur_read'] is None:
        # Dontcache and direct IO also look like this
        rmode = None
        rwhy.append('Storage supplies most READ data, and there is no '
                    'memory pressure. The current IO mode is not known, so '
                    'the cause is not clear. Run as root.')
        rwhy.extend(readahead)
    elif not pressure:
        rmode = 'buffered'
        rwhy.append('Storage supplies most READ data, but there is no '
                    'memory pressure. Buffered IO costs little.')
        rwhy.extend(readahead)
        rwhy.extend(unfilled())
    else:
        # The page cache supplies less than 1 - MISS_HIGH of the READ data.
        # Whether or not the export re-reads evicted data, keeping it in
        # the page cache costs reclaim for little benefit.
        why = ['Storage supplies most READ data, and there is memory '
               'pressure.'] + readahead
        if m['refault_frac'] > REFAULT_FRAC:
            why.append('Other data is evicted and then read again. Less '
                       'page cache use by this export helps that data.')
        rmode, rwhy = uncached(m['avg_read'], LARGE_IO, why,
                               ctx['direct_read'])

    # WRITE
    wwhy = []
    if ctx['cur_write'] not in ('buffered', None):
        wmode = None
        wwhy.append(current_mode('write_io', 'io_cache_write',
                                 ctx['cur_write'], ctx['write_src']) +
                    ' The memory pressure and dirty data values do not '
                    'include buffered WRITEs. Set write_io=buffered and run '
                    'again.')
    elif m['io_write'] < MIN_IO_BYTES:
        wmode = None
        wwhy.append('Not enough WRITE traffic in the interval.')
    elif m['avg_write'] is not None and m['avg_write'] < ctx['write_large']:
        wmode = 'buffered'
        wwhy.append('The average WRITE size is smaller than %s%s. The page '
                    'cache collects small WRITEs into larger units.' %
                    (fmt_bytes(ctx['write_large']), ctx['write_large_why']))
    elif rmode == 'buffered' and m['miss_ratio'] is not None and \
            m['miss_ratio'] < MISS_LOW:
        wmode = 'buffered'
        wwhy.append('READs of this export use the page cache. Buffered '
                    'WRITEs keep written data there for later READs.')
    elif not pressure and m['dirty_bg_frac'] < DIRTY_BG_FRAC:
        wmode = 'buffered'
        wwhy.append('There is no memory pressure, and little dirty data.')
        wwhy.extend(unfilled())
    else:
        wmode, wwhy = uncached(m['avg_write'], ctx['write_large'],
                               ['WRITEs are large and there is memory '
                                'pressure or much dirty data.'],
                               ctx['direct_write'], ctx['direct_write_why'])

    return rmode, rwhy, wmode, wwhy


def fmt_bytes(n):
    if n is None:
        return 'n/a'
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(n) < 1024 or unit == 'TiB':
            return '%.1f %s' % (n, unit) if unit != 'B' else '%d B' % n
        n /= 1024


def fmt_pct(v):
    return 'n/a' if v is None else '%.2f%%' % v


def report(ctx, m, rec):
    rmode, rwhy, wmode, wwhy = rec
    print('Export:            %s' % ctx['path'])
    print('Filesystem:        %s (%s)' % (ctx['fstype'], ctx['source']))
    support = {True: 'supported', False: 'not supported', None: 'unknown'}
    print('Dontcache:         %s' % support[ctx['dontcache']])
    if ctx['direct_write_why']:
        dw = 'not usable over TCP (memory alignment %d bytes)' % \
            ctx['dio_mem_align']
    else:
        dw = support[ctx['direct_write']]
    print('Direct IO:         READ %s, WRITE %s' %
          (support[ctx['direct_read']], dw))
    rot = {True: 'rotational', False: 'not rotational', None: 'unknown'}
    print('Storage:           %s, optimal IO size %s' %
          (rot[ctx['rotational']],
           fmt_bytes(ctx['io_opt']) if ctx['io_opt'] else 'not reported'))
    print('Current modes:     read_io=%s write_io=%s' %
          (ctx['cur_read'] or 'unknown', ctx['cur_write'] or 'unknown'))
    print('Interval:          %.0f s' % m['interval'])
    print()
    print('Export traffic:    read %s, written %s' %
          (fmt_bytes(m['io_read']), fmt_bytes(m['io_write'])))
    if m['miss_source'] == 'device' and len(ctx['fs_exports']) > 1:
        print('Device traffic:    read %s (exports: %s)' %
              (fmt_bytes(m['fs_io_read']), ', '.join(sorted(ctx['fs_exports']))))
    source = {'export': 'io_read_storage', 'device': 'block device'}
    print('Storage reads:     %s' % fmt_bytes(m['storage_read']))
    print('Miss ratio:        %s' %
          ('n/a' if m['miss_ratio'] is None else '%.2f (%s)' %
           (m['miss_ratio'], source[m['miss_source']])))
    print('Avg NFSD READ:     %s (all exports)' % fmt_bytes(m['avg_read']))
    print('Avg NFSD WRITE:    %s (all exports)' % fmt_bytes(m['avg_write']))
    print()
    print('Pages reclaimed:   %d (%s%s)' %
          (m['reclaimed'], fmt_bytes(m['reclaimed'] * PAGE_SIZE),
           '' if m['reclaim_traffic'] is None else
           ', %.2f times the storage traffic of the export' %
           m['reclaim_traffic']))
    print('File refaults:     %d (%.1f%% of reclaimed)' %
          (m['refault'], m['refault_frac'] * 100))
    if m['memcg_cgroups']:
        print('Limit reclaim:     %d pages, %d refaults, PSI some %s, '
              'not counted (cgroups at memory.high or memory.max: %s)' %
              (m['memcg_reclaimed'], m['memcg_refault'],
               fmt_pct(m['memcg_psi_some']), ', '.join(m['memcg_cgroups'])))
    print('Memory PSI:        some %s, full %s' %
          (fmt_pct(m['psi_some']), fmt_pct(m['psi_full'])))
    print('Reclaim CPU:       %.1f%% of one CPU (busiest of kswapd and '
          'kcompactd: %s)' % (m['reclaim_cpu'], m['reclaim_thread'] or 'n/a'))
    print('Direct reclaim:    %d allocstalls, %d pages scanned, %s of '
          'reclaim' % (m['allocstall'], m['pgscan_direct'],
                       fmt_pct(None if m['direct_frac'] is None else
                               m['direct_frac'] * 100)))
    print('Compaction stalls: %d' % m['compact_stall'])
    print('Dirty+Writeback:   %s average, %.0f%% of the background writeback '
          'threshold %s (%s)' %
          (fmt_bytes(m['dirty_kb'] * 1024), m['dirty_bg_frac'] * 100,
           fmt_bytes(m['dirty_bg_kb'] * 1024),
           'device ' + ctx['bdi'] if ctx['bdi'] else 'all devices'))
    print('Free memory:       %s (%s)' %
          (fmt_bytes(m['free_kb'] * 1024),
           'page cache is full' if m['cache_full'] else
           'page cache has not filled'))
    if 'cachestat' in m:
        cs = m['cachestat']
        print('Sampled files:     %d, %d pages cached, %d recently evicted '
              '(%+d)' % (cs['files'], cs['nr_cache'],
                         cs['nr_recently_evicted'],
                         cs['recently_evicted_delta']))
    print()
    print('Recommended read_io: %s' % (rmode or 'unknown'))
    for r in rwhy:
        print('  - ' + r)
    print('Recommended write_io: %s' % (wmode or 'unknown'))
    for r in wwhy:
        print('  - ' + r)
    notes = []
    if ctx['cur_read'] is None or ctx['cur_write'] is None:
        notes.append('Cannot read the global IO modes in %s. Run as root. '
                     'The analysis assumes buffered IO.' % DEBUGFS_NFSD)
    if m['incomplete']:
        notes.append('An export cache entry appeared during the interval '
                     'with counters that started earlier, or left the '
                     'cache. Its traffic is not included. Traffic values '
                     'can be too low.')
    if m['miss_source'] == 'export':
        notes.append('The miss ratio includes readahead and filesystem '
                     'metadata reads.')
    if ctx['uncharged'] and m['miss_source'] == 'device':
        notes.append('%s reads storage from its own threads, so the miss '
                     'ratio uses block device reads.' % ctx['fstype'])
    elif m['miss_source'] == 'device' and \
            ctx['cur_read'] in ('buffered', None):
        notes.append('The kernel does not report io_read_storage. The miss '
                     'ratio uses block device reads. Readahead, metadata and '
                     'local applications also cause device reads. The miss '
                     'ratio is approximate.')
    if m['miss_source'] == 'device' and ctx['fstype'] == 'btrfs':
        notes.append('btrfs can use more than one device. Only %s is '
                     'measured.' % ctx['source'])
    if ctx['direct_write_why'] and ctx['rdma']:
        notes.append('NFSD also listens for RDMA. The WRITE recommendation '
                     'is for clients that use TCP.')
    if not ctx['bdi']:
        notes.append('Cannot read the statistics of the backing device in '
                     '%s. Dirty and Writeback are for all devices.' %
                     DEBUGFS_BDI)
    if ctx['memcg_v1']:
        notes.append('The memory controller uses cgroup v1. The reclaim and '
                     'stalls of cgroups at their memory limit cannot be '
                     'separated, and count as system memory pressure.')
    notes.append('Average IO sizes are for all exports. The command does '
                 'not check if READs and WRITEs are aligned for direct IO. '
                 'Memory metrics are for the full system, not for each '
                 'NUMA node.')
    print()
    for n in notes:
        print('Note: ' + n)


def main():
    p = argparse.ArgumentParser(
        description='Recommend NFSD read_io= and write_io= settings for an '
                    'export. Run while clients use the export with a '
                    'typical workload.')
    p.add_argument('export', help='path of the export')
    p.add_argument('-i', '--interval', type=float, default=60,
                   help='measurement interval in seconds (default: 60)')
    p.add_argument('-s', '--sample-files', type=int, default=0, metavar='N',
                   help='check the page cache state of the N largest files '
                        'in the export with cachestat(2) (default: 0)')
    p.add_argument('-j', '--json', action='store_true',
                   help='print the metrics and recommendation as JSON')
    args = p.parse_args()

    path = os.path.realpath(args.export)
    try:
        st = os.stat(path)
    except OSError as e:
        sys.exit('%s: %s' % (args.export, e.strerror))

    exports = read_export_stats()
    etab = read_etab()
    if not any(k[0] == path for k in exports) and path not in etab:
        sys.exit('%s is not an export: it is not in %s or %s' %
                 (path, EXPORT_STATS, ETAB))

    fstype, source = find_mount(path, st.st_dev)
    block_stat = find_block_stat(st.st_dev, source)

    # The exports whose READs the block device statistics also count.
    # btrfs subvolumes on one device have different st_dev values. Paths
    # with the same root (bind mounts) share counters, so keep one.
    fs_exports = {path}
    roots = {(st.st_dev, st.st_ino)}
    for epath in {k[0] for k in exports} | set(etab):
        try:
            est = os.stat(epath)
        except OSError:
            continue
        root = (est.st_dev, est.st_ino)
        if root in roots:
            continue
        if block_stat is not None:
            esrc = find_mount(epath, est.st_dev)[1]
            same = find_block_stat(est.st_dev, esrc) == block_stat
        else:
            same = est.st_dev == st.st_dev
        if same:
            roots.add(root)
            fs_exports.add(epath)

    rmode, wmode = read_export_modes(path, etab)
    ctx = {
        'path': path,
        'fs_exports': fs_exports,
        'fstype': fstype,
        'source': source,
        'block_stat': block_stat,
        'cur_read': rmode or read_global_mode('io_cache_read'),
        'cur_write': wmode or read_global_mode('io_cache_write'),
        'read_src': 'export' if rmode else 'global',
        'write_src': 'export' if wmode else 'global',
        'files': [],
        'uncharged': (fstype or '').split('.')[0] in UNCHARGED_FS,
        'memcg_v1': os.path.exists(os.path.join(CGROUP_ROOT, 'memory',
                                                'memory.stat')),
    }
    ctx['bdi'], ctx['bdi_stats'] = find_bdi(st.st_dev, fstype, source)
    try:
        sv = os.statvfs(path)
        ctx['fs_used'] = (sv.f_blocks - sv.f_bfree) * sv.f_frsize
    except OSError:
        ctx['fs_used'] = None

    # A WRITE of the size that the storage prefers avoids read-modify-write
    # on parity RAID. Only the page cache can collect smaller WRITEs into
    # units of this size.
    queue = find_queue(block_stat)
    rot = read_int(os.path.join(queue, 'rotational')) if queue else None
    ctx['rotational'] = None if rot is None else rot == 1
    ctx['io_opt'] = (read_int(os.path.join(queue, 'optimal_io_size'))
                     if queue else None) or 0
    ctx['write_large'], ctx['write_large_why'] = LARGE_IO, ''
    # NFSD writes the misaligned start and end of a WRITE up to page
    # boundaries with buffered IO. With large pages, a misaligned WRITE
    # needs several pages to have a direct middle.
    if LARGE_WRITE_PAGES * PAGE_SIZE > ctx['write_large']:
        ctx['write_large'] = LARGE_WRITE_PAGES * PAGE_SIZE
        ctx['write_large_why'] = ' (%d pages)' % LARGE_WRITE_PAGES
    if ctx['write_large'] < ctx['io_opt'] <= MAX_IO_OPT:
        ctx['write_large'] = ctx['io_opt']
        ctx['write_large_why'] = ' (the optimal IO size of the storage)'

    probe = pick_files(path, 1, 20)
    ctx['dontcache'] = probe_dontcache(probe)
    ctx['direct_read'], ctx['direct_write'], ctx['dio_mem_align'] = \
        probe_direct(probe)
    # WRITE data received over TCP is aligned to only XDR_ALIGN bytes in
    # memory. NFSD writes it with buffered IO if the block device needs a
    # larger memory alignment, as device mapper and MD devices do.
    ctx['direct_write_why'] = None
    ctx['rdma'] = rdma_listener()
    if ctx['direct_write'] and ctx['dio_mem_align'] > XDR_ALIGN:
        ctx['direct_write'] = False
        ctx['direct_write_why'] = (
            'NFSD cannot write to this filesystem with direct IO. Its block '
            'device needs %d-byte memory alignment, and WRITE data that '
            'arrives over TCP has only %d-byte alignment.' %
            (ctx['dio_mem_align'], XDR_ALIGN))
    if args.sample_files > 0:
        ctx['cachestat'] = Cachestat()
        ctx['files'] = pick_files(path, args.sample_files,
                                  max(args.sample_files * 20, FILE_SCAN))
        if ctx['files'] and ctx['cachestat'](ctx['files'][0]) is None:
            print('cachestat(2) is not available. File sampling is off.',
                  file=sys.stderr)
            ctx['files'] = []

    try:
        a, b, dirty = measure(ctx, args.interval)
    except KeyboardInterrupt:
        sys.exit(1)

    m = analyze(ctx, a, b, dirty)
    rec = recommend(ctx, m)
    if args.json:
        out = {'export': path, 'fstype': fstype, 'source': source,
               'bdi': ctx['bdi'],
               'dontcache': ctx['dontcache'],
               'direct': {'read': ctx['direct_read'],
                          'write': ctx['direct_write'],
                          'mem_align': ctx['dio_mem_align'],
                          'write_reason': ctx['direct_write_why']},
               'storage': {'rotational': ctx['rotational'],
                           'optimal_io_size': ctx['io_opt'],
                           'large_write': ctx['write_large']},
               'current': {'read_io': ctx['cur_read'],
                           'write_io': ctx['cur_write'],
                           'read_io_source': ctx['read_src'],
                           'write_io_source': ctx['write_src']},
               'metrics': {**m, 'fs_exports': sorted(fs_exports)},
               'recommendation': {'read_io': rec[0], 'read_reasons': rec[1],
                                  'write_io': rec[2], 'write_reasons': rec[3]}}
        print(json.dumps(out, indent=2))
    else:
        report(ctx, m, rec)


if __name__ == '__main__':
    main()

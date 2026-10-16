#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Recommend NFSD read and write IO modes (riomode= and wiomode=) for an
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
NFSD_STATS = '/proc/net/rpc/nfsd'
DEBUGFS_NFSD = '/sys/kernel/debug/nfsd'

IOMODES = ['buffered', 'dontcache', 'direct']
COUNTERS = ('io_read', 'io_write', 'io_read_storage')

RWF_DONTCACHE = 0x80
AT_FDCWD = -100
STATX_DIOALIGN = 0x2000
STATX_DIO_READ_ALIGN = 0x20000

# Heuristic thresholds. These are starting points, not tuned values.
MIN_IO_BYTES = 64 << 20          # less traffic than this is not conclusive
MISS_LOW = 0.5                   # below: page cache supplies most READ data
MISS_HIGH = 0.8                  # above: storage supplies most READ data
RECLAIM_FRAC = 0.01              # pages reclaimed per minute / MemTotal
REFAULT_FRAC = 0.1               # refaults / pages reclaimed
PSI_SOME_PCT = 1.0
PSI_FULL_PCT = 1.0
RECLAIM_CPU_PCT = 10.0           # kswapd + kcompactd, % of one CPU
STALLS_PER_MIN = 10              # allocation + compaction stalls
DIRTY_FRAC = 0.05                # (Dirty + Writeback) / MemTotal
LARGE_IO = 64 << 10              # average READ/WRITE size for direct IO

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


def read_export_modes(path):
    """Return the per-export (riomode, wiomode) of path, None if unset."""
    text = read_file(EXPORT_CONTENT) or ''
    rmode = wmode = None
    for line in text.splitlines():
        if line.startswith('#') or '\t' not in line:
            continue
        epath, _, rest = line.partition('\t')
        if unescape(epath) != path:
            continue
        m = re.search(r'riomode=(\w+)', rest)
        if m:
            rmode = m.group(1)
        m = re.search(r'wiomode=(\w+)', rest)
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


def read_psi():
    """Return {'some': total_usec, 'full': total_usec}."""
    out = {}
    for line in (read_file('/proc/pressure/memory') or '').splitlines():
        fields = line.split()
        for f in fields[1:]:
            if f.startswith('total='):
                out[fields[0]] = int(f[6:])
    return out


def read_reclaim_cpu_ticks():
    ticks = 0
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        comm = read_file('/proc/%s/comm' % pid)
        if not comm or not comm.startswith(('kswapd', 'kcompactd')):
            continue
        stat = read_file('/proc/%s/stat' % pid)
        if stat:
            fields = stat.rpartition(')')[2].split()
            ticks += int(fields[11]) + int(fields[12])
    return ticks


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


def read_block(path):
    """Return (read_bytes, write_bytes) of a block device."""
    if path is None:
        return None
    fields = (read_file(path) or '').split()
    if len(fields) < 7:
        return None
    return int(fields[2]) * 512, int(fields[6]) * 512


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
    """Return (read_ok, write_ok) for direct IO, (None, None) if unknown.

    NFSD uses the STATX_DIOALIGN and STATX_DIO_READ_ALIGN values of the
    file. Without them, NFSD does not use direct IO. A direct READ or
    WRITE then uses dontcache if possible, else buffered IO.
    """
    try:
        statx = ctypes.CDLL(None, use_errno=True).statx
    except AttributeError:
        return None, None
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
        return bool(read_align), bool(mem_align and offset_align)
    return None, None


def pick_files(root, count):
    """Return the largest regular files under root, on the same filesystem."""
    dev = os.stat(root).st_dev
    found = []
    stack = [root]
    budget = count * 20
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
        'reclaim_ticks': read_reclaim_cpu_ticks(),
        'block': read_block(ctx['block_stat']),
    }
    if ctx['files']:
        cs = [ctx['cachestat'](p) for p in ctx['files']]
        s['cachestat'] = [c for c in cs if c is not None]
    return s


def export_delta(a, b, paths):
    """Sum the counter deltas of all entries for paths.

    The kernel keeps the counters of an export across export cache
    updates, but does not list an entry while it is out of the cache.
    An entry that is new in b, or whose start time changed, counts only
    if its counters started during the interval. Otherwise its traffic
    in the interval is not known. The start time is CLOCK_MONOTONIC
    seconds, the clock of time.monotonic().

    Returns (deltas, incomplete). A counter that an entry does not
    report is None in deltas.
    """
    out = dict.fromkeys(COUNTERS, 0)
    incomplete = False
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


def analyze(ctx, a, b):
    dt = b['time'] - a['time']
    va, vb = a['vmstat'], b['vmstat']

    def dv(name):
        return vb.get(name, 0) - va.get(name, 0)

    meminfo = read_kv('/proc/meminfo')
    mem_pages = meminfo.get('MemTotal', 0) * 1024 // os.sysconf('SC_PAGE_SIZE')

    m = {'interval': dt}
    d, m['incomplete'] = export_delta(a, b, {ctx['path']})
    m['io_read'], m['io_write'] = d['io_read'], d['io_write']
    fs, fs_incomplete = export_delta(a, b, ctx['fs_exports'])
    m['fs_io_read'] = fs['io_read']

    # io_read_storage is exact for the export. Block device reads also
    # count other exports and local applications on the device.
    m['storage_read'] = m['miss_ratio'] = m['miss_source'] = None
    if d['io_read_storage'] is not None:
        if d['io_read']:
            m['storage_read'] = d['io_read_storage']
            m['miss_ratio'] = m['storage_read'] / d['io_read']
            m['miss_source'] = 'export'
    elif a['block'] and b['block'] and fs['io_read']:
        m['storage_read'] = b['block'][0] - a['block'][0]
        m['miss_ratio'] = m['storage_read'] / fs['io_read']
        m['miss_source'] = 'device'
        m['incomplete'] = m['incomplete'] or fs_incomplete

    na, nb = a['nfsd'], b['nfsd']
    reads = nb['reads'] - na['reads']
    writes = nb['writes'] - na['writes']
    m['avg_read'] = (nb['read_bytes'] - na['read_bytes']) // reads if reads else None
    m['avg_write'] = (nb['write_bytes'] - na['write_bytes']) // writes if writes else None

    m['reclaimed'] = dv('pgsteal_kswapd') + dv('pgsteal_direct')
    m['refault'] = dv('workingset_refault_file')
    m['activate'] = dv('workingset_activate_file')
    m['allocstall'] = sum(vb[k] - va.get(k, 0) for k in vb
                          if k.startswith('allocstall'))
    m['pgscan_direct'] = dv('pgscan_direct')
    m['compact_stall'] = dv('compact_stall')
    # Normalize to one minute so the threshold does not depend on interval
    m['reclaim_frac'] = m['reclaimed'] * 60 / (mem_pages * dt) if mem_pages else 0
    m['refault_frac'] = m['refault'] / m['reclaimed'] if m['reclaimed'] else 0

    for kind in ('some', 'full'):
        if kind in a['psi'] and kind in b['psi']:
            m['psi_' + kind] = (b['psi'][kind] - a['psi'][kind]) / (dt * 1e4)
        else:
            m['psi_' + kind] = None

    m['reclaim_cpu'] = (b['reclaim_ticks'] - a['reclaim_ticks']) * 100.0 / \
        (os.sysconf('SC_CLK_TCK') * dt)

    total = meminfo.get('MemTotal', 0)
    dirty = meminfo.get('Dirty', 0) + meminfo.get('Writeback', 0)
    m['dirty_frac'] = dirty / total if total else 0

    if 'cachestat' in b:
        csa = {k: sum(c[k] for c in a['cachestat']) for k in Cachestat.FIELDS}
        csb = {k: sum(c[k] for c in b['cachestat']) for k in Cachestat.FIELDS}
        m['cachestat'] = {'files': len(b['cachestat']), **csb,
                          'recently_evicted_delta':
                              csb['nr_recently_evicted'] - csa['nr_recently_evicted']}
    return m


def recommend(ctx, m):
    """Return (riomode, read_reasons, wiomode, write_reasons)."""
    pressure = m['reclaim_frac'] > RECLAIM_FRAC or \
        (m['psi_some'] or 0) > PSI_SOME_PCT
    costly = (m['psi_full'] or 0) > PSI_FULL_PCT or \
        m['reclaim_cpu'] > RECLAIM_CPU_PCT or \
        (m['allocstall'] + m['compact_stall']) * 60 / m['interval'] > \
        STALLS_PER_MIN
    dontcache_ok = ctx['dontcache'] is not False
    fsname = ctx['fstype'] or 'This filesystem'

    def uncached(avg, why, direct):
        large = avg is not None and avg >= LARGE_IO
        direct_ok = direct is not False
        if direct is None or ctx['dontcache'] is None:
            why = why + ['IO mode support was not verified. No readable '
                         'file was found in the export.']
        if costly and large and direct_ok:
            return 'direct', why + ['Page reclaim is costly and the average '
                                    'IO size is large.']
        if dontcache_ok:
            return 'dontcache', why
        if large and direct_ok:
            return 'direct', why + ['%s does not support dontcache.' %
                                    fsname]
        if direct_ok:
            return 'buffered', why + ['%s does not support dontcache, and '
                                      'the average IO size is small for '
                                      'direct IO.' % fsname]
        return 'buffered', why + ['%s supports neither dontcache nor direct '
                                  'IO. NFSD uses buffered IO for all modes.' %
                                  fsname]

    readahead = []
    if m['miss_ratio'] is not None and m['miss_ratio'] > 1:
        readahead = ['Storage read more data than NFSD returned. Readahead '
                     'reads data that clients do not request, for example '
                     'with small random READs.']

    # READ
    rwhy = []
    if ctx['cur_read'] not in ('buffered', None):
        rmode = None
        rwhy.append('The export uses riomode=%s. The miss ratio is not '
                    'meaningful. Set riomode=buffered and run again.' %
                    ctx['cur_read'])
    elif m['io_read'] < MIN_IO_BYTES:
        rmode = None
        rwhy.append('Not enough READ traffic in the interval.')
    elif m['miss_ratio'] is None:
        rmode = None
        rwhy.append('No block device statistics for this filesystem. '
                    'The miss ratio is not available.')
    elif m['miss_ratio'] < MISS_LOW:
        rmode = 'buffered'
        rwhy.append('The page cache supplies most READ data.')
    elif m['miss_ratio'] < MISS_HIGH:
        rmode = 'buffered'
        rwhy.append('The page cache supplies part of the READ data.')
        if m.get('cachestat', {}).get('recently_evicted_delta', 0) > 0:
            rwhy.append('Page reclaim evicts data of this export. Other '
                        'exports with read-once data can use dontcache '
                        'or direct IO to give more page cache to this one.')
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
    else:
        why = ['Storage supplies most READ data, and there is memory '
               'pressure.'] + readahead
        evicted = m.get('cachestat', {}).get('recently_evicted_delta')
        if m['refault_frac'] > REFAULT_FRAC and evicted and evicted > 0:
            rmode = 'buffered'
            rwhy = why + ['Data of this export is evicted and then read '
                          'again. Its working set does not fit in the page '
                          'cache, and dontcache or direct IO does not help '
                          'it. Other exports that read data only one time '
                          'can use dontcache or direct IO to give more page '
                          'cache to this one.']
        else:
            if m['refault_frac'] > REFAULT_FRAC:
                why.append('Other data is evicted and then read again. Less '
                           'page cache use by this export helps that data.')
                if evicted is None:
                    why.append('The evicted data can also be data of this '
                               'export. Run with -s to check.')
            rmode, rwhy = uncached(m['avg_read'], why, ctx['direct_read'])

    # WRITE
    wwhy = []
    if m['io_write'] < MIN_IO_BYTES:
        wmode = None
        wwhy.append('Not enough WRITE traffic in the interval.')
    elif m['avg_write'] is not None and m['avg_write'] < LARGE_IO:
        wmode = 'buffered'
        wwhy.append('The average WRITE size is small. The page cache '
                    'collects small WRITEs into larger units.')
    elif rmode == 'buffered' and m['miss_ratio'] is not None and \
            m['miss_ratio'] < MISS_LOW:
        wmode = 'buffered'
        wwhy.append('READs of this export use the page cache. Buffered '
                    'WRITEs keep written data there for later READs.')
    elif not pressure and m['dirty_frac'] < DIRTY_FRAC:
        wmode = 'buffered'
        wwhy.append('There is no memory pressure, and little dirty data.')
    else:
        wmode, wwhy = uncached(m['avg_write'],
                               ['WRITEs are large and there is memory '
                                'pressure or much dirty data.'],
                               ctx['direct_write'])
    if ctx['cur_write'] not in ('buffered', None):
        wwhy.append('The export uses wiomode=%s. The memory pressure values '
                    'do not include buffered WRITEs.' % ctx['cur_write'])

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
    print('Direct IO:         READ %s, WRITE %s' %
          (support[ctx['direct_read']], support[ctx['direct_write']]))
    print('Current modes:     riomode=%s wiomode=%s' %
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
    print('Pages reclaimed:   %d (%.2f%% of memory per minute)' %
          (m['reclaimed'], m['reclaim_frac'] * 100))
    print('File refaults:     %d (%.1f%% of reclaimed)' %
          (m['refault'], m['refault_frac'] * 100))
    print('Memory PSI:        some %s, full %s' %
          (fmt_pct(m['psi_some']), fmt_pct(m['psi_full'])))
    print('Reclaim CPU:       %.1f%% of one CPU (kswapd, kcompactd)' %
          m['reclaim_cpu'])
    print('Direct reclaim:    %d allocstalls, %d pages scanned' %
          (m['allocstall'], m['pgscan_direct']))
    print('Compaction stalls: %d' % m['compact_stall'])
    print('Dirty+Writeback:   %.1f%% of memory' % (m['dirty_frac'] * 100))
    if 'cachestat' in m:
        cs = m['cachestat']
        print('Sampled files:     %d, %d pages cached, %d recently evicted '
              '(%+d)' % (cs['files'], cs['nr_cache'],
                         cs['nr_recently_evicted'],
                         cs['recently_evicted_delta']))
    print()
    print('Recommended riomode: %s' % (rmode or 'unknown'))
    for r in rwhy:
        print('  - ' + r)
    print('Recommended wiomode: %s' % (wmode or 'unknown'))
    for r in wwhy:
        print('  - ' + r)
    notes = []
    if ctx['cur_read'] is None or ctx['cur_write'] is None:
        notes.append('Cannot read the global IO modes in %s. Run as root. '
                     'The analysis assumes buffered IO.' % DEBUGFS_NFSD)
    if m['incomplete']:
        notes.append('An export cache entry appeared during the interval '
                     'with counters that started earlier. Its traffic is '
                     'not included. Traffic values can be too low.')
    if m['miss_source'] == 'export':
        notes.append('The miss ratio includes readahead and filesystem '
                     'metadata reads.')
    elif m['miss_source'] == 'device' and \
            ctx['cur_read'] in ('buffered', None):
        notes.append('The kernel does not report io_read_storage. The miss '
                     'ratio uses block device reads. Readahead, metadata and '
                     'local applications also cause device reads. The miss '
                     'ratio is approximate.')
    if m['miss_source'] == 'device' and ctx['fstype'] == 'btrfs':
        notes.append('btrfs can use more than one device. Only %s is '
                     'measured.' % ctx['source'])
    notes.append('Average IO sizes are for all exports. Memory metrics are '
                 'for the full system.')
    print()
    for n in notes:
        print('Note: ' + n)


def main():
    p = argparse.ArgumentParser(
        description='Recommend NFSD riomode= and wiomode= settings for an '
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
    if not any(k[0] == path for k in exports):
        sys.exit('%s is not an active export in %s' % (path, EXPORT_STATS))

    fstype, source = find_mount(path, st.st_dev)
    block_stat = find_block_stat(st.st_dev, source)

    # The exports whose READs the block device statistics also count.
    # btrfs subvolumes on one device have different st_dev values. Paths
    # with the same root (bind mounts) share counters, so keep one.
    fs_exports = {path}
    roots = {(st.st_dev, st.st_ino)}
    for epath, _ in exports:
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

    rmode, wmode = read_export_modes(path)
    ctx = {
        'path': path,
        'fs_exports': fs_exports,
        'fstype': fstype,
        'source': source,
        'block_stat': block_stat,
        'cur_read': rmode or read_global_mode('io_cache_read'),
        'cur_write': wmode or read_global_mode('io_cache_write'),
        'files': [],
    }
    probe = pick_files(path, 1)
    ctx['dontcache'] = probe_dontcache(probe)
    ctx['direct_read'], ctx['direct_write'] = probe_direct(probe)
    if args.sample_files > 0:
        ctx['cachestat'] = Cachestat()
        ctx['files'] = pick_files(path, args.sample_files)
        if ctx['files'] and ctx['cachestat'](ctx['files'][0]) is None:
            print('cachestat(2) is not available. File sampling is off.',
                  file=sys.stderr)
            ctx['files'] = []

    try:
        a = sample(ctx)
        time.sleep(args.interval)
        b = sample(ctx)
    except KeyboardInterrupt:
        sys.exit(1)

    m = analyze(ctx, a, b)
    rec = recommend(ctx, m)
    if args.json:
        out = {'export': path, 'fstype': fstype, 'source': source,
               'dontcache': ctx['dontcache'],
               'direct': {'read': ctx['direct_read'],
                          'write': ctx['direct_write']},
               'current': {'riomode': ctx['cur_read'],
                           'wiomode': ctx['cur_write']},
               'metrics': {**m, 'fs_exports': sorted(fs_exports)},
               'recommendation': {'riomode': rec[0], 'read_reasons': rec[1],
                                  'wiomode': rec[2], 'write_reasons': rec[3]}}
        print(json.dumps(out, indent=2))
    else:
        report(ctx, m, rec)


if __name__ == '__main__':
    main()

"""Summarize a heapprofd trace of the app: what is still allocated, by crate and by call site.

Run through `scripts/profile/android-heap.sh report`, which supplies the symbol copy and
llvm-symbolizer. Rows from trace processor are deltas per dump (frees are negative), so summing a
call site's rows gives what it still holds at the last dump: everything allocated since heapprofd
attached and never freed. A leak is a site whose sum keeps growing from dump to dump.

The shipped library is stripped, so its frames come back as bare offsets. They are named here by
running llvm-symbolizer over the CI symbol copy, which must have the SAME build id as the library
in the trace: symbols from another build would name the wrong functions, so a mismatch is fatal.
"""

import argparse
import collections
import os
import re
import struct
import subprocess
import sys

from perfetto.trace_processor import TraceProcessor

LIB = 'libiroh_location.so'

# Frames that are the allocator or a container growing, never the owner. The first frame from the
# leaf up that matches none of these is the call site the bytes are booked against.
PLUMBING = re.compile(
    r'^(malloc|calloc|realloc|posix_memalign|aligned_alloc|memalign|operator new|scudo|je_|'
    r'__rust_|__rg_|__rdl_|_rjem_|'
    r'iroh_location::alloc_stats|alloc::|core::|std::alloc|hashbrown::|smallvec::|bytes::|'
    r'<alloc::|<core::|<hashbrown::|<smallvec::|<bytes::|<std::|std::collections|'
    r'tokio::runtime::task::|<tokio::runtime::task::|serde::|<serde|postcard::|<postcard)'
)


def build_id(path):
    """The GNU build id of an ELF file, as lowercase hex, or None."""
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != b'\x7fELF' or data[4] != 2:
        return None
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum = struct.unpack_from('<HH', data, 0x3A)
    for i in range(shnum):
        sh_type, = struct.unpack_from('<I', data, shoff + i * shentsize + 4)
        if sh_type != 7:  # SHT_NOTE
            continue
        off, size = struct.unpack_from('<QQ', data, shoff + i * shentsize + 0x18)
        pos = off
        while pos + 12 <= off + size:
            namesz, descsz, ntype = struct.unpack_from('<III', data, pos)
            name_end = pos + 12 + ((namesz + 3) & ~3)
            if ntype == 3 and data[pos + 12:pos + 12 + namesz].rstrip(b'\0') == b'GNU':
                return data[name_end:name_end + descsz].hex()
            pos = name_end + ((descsz + 3) & ~3)
    return None


def symbolize(symbolizer, obj, addresses):
    """{address: function name} for every address, through one llvm-symbolizer process."""
    if not addresses:
        return {}
    addresses = sorted(addresses)
    out = subprocess.run(
        [symbolizer, '--obj', obj, '--functions=linkage', '--demangle', '--no-inlines',
         '--output-style=GNU'],
        input='\n'.join(hex(a) for a in addresses) + '\n',
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    # GNU style: two lines per address, the function then file:line.
    names = {}
    for i, address in enumerate(addresses):
        name = out[2 * i] if 2 * i < len(out) else '??'
        names[address] = name
    return names


def crate_of(name):
    name = name.lstrip('<')
    m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)::', name)
    return m.group(1) if m else name.split('(')[0][:40]


def mib(n):
    return f'{n / (1 << 20):8.1f} MiB'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--trace', required=True)
    ap.add_argument('--symbols', required=True)
    ap.add_argument('--symbolizer', required=True)
    ap.add_argument('--top', type=int, default=30)
    args = ap.parse_args()

    tp = TraceProcessor(trace=args.trace)

    mappings = {r.id: r for r in tp.query(
        'select id, name, build_id, load_bias from stack_profile_mapping')}
    copies = {}
    for dirpath, _, files in os.walk(args.symbols):
        if LIB in files:
            path = os.path.join(dirpath, LIB)
            copies.setdefault(build_id(path), path)
    # The library is mapped straight out of the APK, so its mapping is named by the APK (or
    # `base.apk!libiroh_location.so`, from its soname). The build id is what identifies it.
    ours = [m for m in mappings.values() if (m.build_id or '').lower() in copies]
    if not ours:
        named = [m for m in mappings.values() if m.name and LIB in m.name]
        listing = '\n'.join(f'  {bid or "no build id"}  {path}' for bid, path in copies.items())
        if named and not any(m.build_id for m in named):
            sys.exit(f'{LIB} in the trace has no build id: the installed build predates '
                     '2026-11-21, so its frames cannot be named. Install a newer internal build.')
        sys.exit(f'no mapping in the trace matches a symbol copy under {args.symbols}:\n'
                 f'{listing}\nWrong run, or a build from before 2026-11-21 (no build id).')
    wanted = ours[0].build_id.lower()
    obj = copies[wanted]

    frames = {}
    rel = collections.defaultdict(set)
    for r in tp.query('select id, name, mapping, rel_pc from stack_profile_frame'):
        frames[r.id] = r
        if r.mapping in {m.id for m in ours}:
            rel[r.mapping].add(r.rel_pc)
    names = {}
    for mid, pcs in rel.items():
        bias = mappings[mid].load_bias or 0
        resolved = symbolize(args.symbolizer, obj, {pc + bias for pc in pcs})
        for pc in pcs:
            names[(mid, pc)] = resolved.get(pc + bias, '??')

    def frame_name(fid):
        f = frames[fid]
        if (f.mapping, f.rel_pc) in names:
            return names[(f.mapping, f.rel_pc)]
        if f.name:
            return f.name
        m = mappings.get(f.mapping)
        return f'{os.path.basename(m.name) if m and m.name else "?"}+{f.rel_pc:#x}'

    parent, frame_of = {}, {}
    for r in tp.query('select id, parent_id, frame_id from stack_profile_callsite'):
        parent[r.id] = r.parent_id
        frame_of[r.id] = r.frame_id

    stack_cache = {}

    def stack(callsite):
        """Frame names from the leaf (the allocator) up to the root."""
        if callsite in stack_cache:
            return stack_cache[callsite]
        out, c = [], callsite
        while c is not None:
            out.append(frame_name(frame_of[c]))
            c = parent.get(c)
        stack_cache[callsite] = out
        return out

    def site(callsite):
        for name in stack(callsite):
            if not PLUMBING.match(name):
                return name
        return stack(callsite)[-1]

    held = collections.Counter()
    count = collections.Counter()
    by_ts = collections.defaultdict(collections.Counter)
    for r in tp.query('select ts, callsite_id, count, size from heap_profile_allocation'):
        held[r.callsite_id] += r.size
        count[r.callsite_id] += r.count
        by_ts[r.ts][r.callsite_id] += r.size

    sites, crates = collections.Counter(), collections.Counter()
    site_example, site_count = {}, collections.Counter()
    for cs, size in held.items():
        s = site(cs)
        sites[s] += size
        site_count[s] += count[cs]
        crates[crate_of(s)] += size
        if size > 0 and size >= held.get(site_example.get(s), 0):
            site_example[s] = cs

    dumps = sorted(by_ts)
    total = sum(held.values())
    print(f'{len(dumps)} dumps; still held at the last one, of what was allocated after attach: '
          f'{mib(total).strip()}')
    print(f'library {LIB} build id {wanted}, symbols {obj}\n')

    print('By crate (the first frame above the allocator):')
    for crate, size in crates.most_common(15):
        if size <= 0:
            break
        print(f'  {mib(size)}  {crate}')

    # How each top crate grew from dump to dump: a leak climbs, churn goes up and down.
    top = [c for c, s in crates.most_common(6) if s > 0]
    if len(dumps) > 1 and top:
        print('\nHeld over time (cumulative, per dump):')
        print('  ' + ' '.join(f'{c[:14]:>14}' for c in top))
        running = collections.Counter()
        for ts in dumps:
            for cs, size in by_ts[ts].items():
                running[crate_of(site(cs))] += size
            print('  ' + ' '.join(f'{running[c] / (1 << 20):13.1f}M' for c in top))

    print(f'\nTop {args.top} call sites:')
    for name, size in sites.most_common(args.top):
        if size <= 0:
            break
        print(f'\n{mib(size)}  {site_count[name]:>9} live allocs  {name}')
        for frame in stack(site_example[name])[:18]:
            print(f'      {frame}')


if __name__ == '__main__':
    main()

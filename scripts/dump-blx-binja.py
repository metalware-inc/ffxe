#!/usr/bin/env python3
"""Dump indirect call/branch (BLX <Rm>, BX <Rm>) instructions from the FFXE dataset to a CSV."""
import os
import csv
import glob

import binaryninja as bn

SCRIPTS = os.path.dirname(os.path.realpath(__file__))
EXAMPLES = os.path.join(SCRIPTS, os.pardir, "examples")
OUT = os.path.join(SCRIPTS, "blx-binja.csv")


def read(path):
    with open(path) as f:
        return f.read().strip()


def discover():
    """Yield (name, path, base, vtbases); base/vtbases are None for ELF inputs."""
    for elf in sorted(glob.glob(os.path.join(EXAMPLES, "unit-tests", "*.elf"))):
        yield os.path.basename(elf), elf, None, None
    for d in sorted(glob.glob(os.path.join(EXAMPLES, "real-world", "*", ""))):
        bins = glob.glob(os.path.join(d, "*.bin"))
        if not bins:
            continue
        base = int(read(os.path.join(d, "base_addr.txt")), 0)
        vtbases = [int(x, 0) for x in read(os.path.join(d, "vtbases.txt")).split(",")]
        yield os.path.basename(bins[0]), bins[0], base, vtbases


def load(path, base, vtbases):
    if base is None:
        return bn.load(path)
    bv = bn.load(path, options={
        "loader.architecture": "thumb2",
        "loader.platform": "thumb2",
        "loader.imageBase": base,
    })
    raw = open(path, "rb").read()
    for vt in vtbases:
        for off in range(0, 0x400, 4):
            a = vt - base + off
            if not 0 <= a <= len(raw) - 4:
                break
            ptr = int.from_bytes(raw[a:a + 4], "little")
            if ptr & 1 and base <= (ptr & ~1) < base + len(raw):
                bv.add_function(ptr & ~1)
    bv.update_analysis_and_wait()
    return bv


def call_sites(bv):
    sites = set()
    for func in bv.functions:
        for tokens, addr in func.instructions:
            disasm = " ".join("".join(t.text for t in tokens).split())
            if not disasm.lower().startswith(("bx ", "blx ")):
                continue
            hw = int.from_bytes(bv.read(addr, 2), "little")
            rm = (hw >> 3) & 0xf
            is_blx = (hw & 0xFF87) == 0x4780              # BLX <Rm>: indirect call
            is_bx = (hw & 0xFF87) == 0x4700 and rm != 14  # BX <Rm>: indirect branch (bx lr is a return)
            if is_blx or is_bx:
                sites.add((addr, disasm))
    return sorted(sites)


def main():
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["firmware", "pc", "disasm", "targets"])
        for name, path, base, vtbases in discover():
            bv = load(path, base, vtbases)
            sites = call_sites(bv)
            for pc, disasm in sites:
                w.writerow([name, hex(pc), disasm, ""])
            bv.file.close()
            print(f"  {name:<28} {len(sites):>4} sites")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()

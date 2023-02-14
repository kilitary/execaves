import os
import sys
from mmap import *
import pandas as pd
import json
from pprint import pprint
from capstone import *
from xprint import *
from caps import *

cave_dir = r'H:\hollow-scan'
scan_report = {}
dump_report = {}
md = None
sign = "\xc3\xcc"

def mmap_io_find(filename: str, what: str):
    try:
        with open(filename, mode="rb") as file:
            try:
                with mmap(file.fileno(), length=0, access=ACCESS_READ) as mm:
                    search_file(mm, what)
            except Exception as e:
                print(f"\nmmap exception: {e}")
    except Exception as e:
        print(f"\nopen: {e}")

def search_file(mm: object, what: str):
    ptr = 1
    while ptr > 0:
        ptr = mm.find(bytes(what, 'utf-8'))
        if ptr > 0:
            try:
                data = mm[ptr:ptr + 100]
                print(f"{ptr} 0x{ptr:08x} {to_hex(data, prefix_0x=False)}")

                for insn in md.disasm(data, 0x1000):
                    print_insn_detail(CS_MODE_64, insn)

            except Exception as e:
                print(f"disasm: {e}")
        mm.seek(ptr + 1)

def scan_files(path):
    try:
        print(f'path: {scan_report["main_image_path"]}')

        files = os.listdir(path)
        for file in files:
            size = os.path.getsize(os.path.join(path, file)) / 1024.0 / 1024.0

            # print(f"#{num:-3d} {file}, {size / 1024.0 / 1024.0:.2f} Mb" + (" " * 50))
            mmap_path = os.path.join(path, file)

            try:
                if mmap_path.endswith(('dmp', 'dll', 'exe', 'shc')):
                    print(f'\t-> inspecting {os.path.basename(mmap_path)} {size:.2f}MB')
                    mmap_io_find(mmap_path, sign)
            except Exception as e:
                print(f"\nmmap_io_find exception: {e}")

    except Exception as e:
        print(f"\ne: {e}")

def read_json(path):
    try:
        with open(path, 'r') as f:
            r = json.load(f)
    except Exception as e:
        r = {}
    return r

def main():

    global scan_report, dump_report, md, sign

    print(f'searching for "{sign}"')

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    dirs = os.listdir(cave_dir)

    for dir in dirs:
        d = os.path.join(cave_dir, dir)
        if not os.path.isdir(d):
            continue

        dirs2 = os.listdir(d)

        print(f'processing {d} ({len(dirs2)} suspects)')

        for dir2 in dirs2:
            path = os.path.join(d, dir2)
            scan_report = read_json(os.path.join(path, 'scan_report.json'))
            dump_report = read_json(os.path.join(path, 'dump_report.json'))
            scan_files(path)

if __name__ == '__main__':
    main()

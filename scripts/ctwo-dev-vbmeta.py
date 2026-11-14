#!/usr/bin/env python3
"""Create an unsigned flag-1 development vbmeta, preserving stock descriptors."""
import argparse, hashlib, pathlib, struct, subprocess, tempfile

p = argparse.ArgumentParser()
p.add_argument('--stock', required=True, type=pathlib.Path)
p.add_argument('--output', required=True, type=pathlib.Path)
a = p.parse_args()
stock = a.stock.read_bytes()
if hashlib.sha256(stock).hexdigest() != '6390f95382c24a8d881c155df72adabf114e1158fc84075d2170630b8e63d026':
    raise SystemExit('Stock vbmeta hash mismatch')
if a.output.exists():
    raise SystemExit('Output already exists')
rollback = struct.unpack_from('>Q', stock, 112)[0]
location = struct.unpack_from('>I', stock, 124)[0]

def descriptors(b):
    if b[:4] != b'AVB0':
        raise ValueError('Invalid vbmeta header')
    auth = struct.unpack_from('>Q', b, 12)[0]
    offset, size = struct.unpack_from('>QQ', b, 96)
    start = 256 + auth + offset
    if start + size > len(b):
        raise ValueError('Invalid descriptor bounds')
    return start, size

with tempfile.TemporaryDirectory(dir=a.output.parent) as td:
    candidate = pathlib.Path(td) / 'vbmeta.img'
    subprocess.run(['avbtool', 'make_vbmeta_image', '--include_descriptors_from_image', str(a.stock), '--algorithm', 'NONE', '--flags', '1', '--rollback_index', str(rollback), '--rollback_index_location', str(location), '--padding_size', str(len(stock)), '--output', str(candidate)], check=True)
    data = bytearray(candidate.read_bytes())
    src, n = descriptors(stock)
    dst, m = descriptors(data)
    if n != m or len(data) != len(stock):
        raise SystemExit('Unexpected descriptor or image size')
    data[dst:dst+m] = stock[src:src+n]
    candidate.write_bytes(data)
    if (data[dst:dst+m] != stock[src:src+n] or
            struct.unpack_from('>Q', data, 12)[0] != 0 or
            struct.unpack_from('>I', data, 28)[0] != 0 or
            struct.unpack_from('>Q', data, 112)[0] != rollback or
            struct.unpack_from('>I', data, 120)[0] != 1 or
            struct.unpack_from('>I', data, 124)[0] != location):
        raise SystemExit('Development vbmeta header or descriptors differ from request')
    info = subprocess.check_output(['avbtool', 'info_image', '--image', str(candidate)], text=True)
    if 'Algorithm:                NONE' not in info or 'Flags:                    1' not in info:
        raise SystemExit('Unexpected candidate AVB metadata')
    with a.output.open('xb') as out:
        out.write(data)
print('[ok] unsigned development vbmeta:', a.output)
print('Bootloader acceptance is unverified.')

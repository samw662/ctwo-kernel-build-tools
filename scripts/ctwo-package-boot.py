#!/usr/bin/env python3
"""Package a boot pair only after validating native vendor-ramdisk inputs."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

STOCK_BOOT = '5a764e10fd6cc9afd1c9661b1dbabd72b29bd128c0c192b41046fc591e4b94df'
STOCK_VENDOR_BOOT = '05e1922237a60a5c1a400ea775d4774eaa0e56cca76a2f883e7fc33c0650c524'
RELEASE = '6.1.128—WearyStars⭐'
MAGIC = b'~Module signature appended~\n'
BOOT_CAPACITY = 100663296
VENDOR_BOOT_CAPACITY = 100663296
RC0_MANIFEST_SHA256 = 'f50f7d6cd636428c2b68d4e1fec72577df47e7ba88ec0b19aa964975e5bb8753'

def fail(message):
    raise SystemExit(message)

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)

def verify_avb(path, capacity, partition, salt):
    if path.stat().st_size != capacity or capacity % 4096:
        fail(f'Invalid partition size or alignment: {path}')
    with path.open('rb') as f:
        f.seek(-64, os.SEEK_END)
        footer = f.read(64)
    magic, major, minor, original, offset, size = struct.unpack('!4s2I3Q28x', footer)
    if (magic != b'AVBf' or major != 1 or minor != 0 or original <= 0 or
        original % 4096 or offset != original or offset % 4096 or
        size <= 0 or offset + size > capacity - 4096):
        fail(f'Invalid AVB footer or payload boundaries: {path}')
    text = subprocess.check_output(['avbtool', 'info_image', '--image', str(path)], text=True)
    expected = (r'^Algorithm:\s+NONE\s*$', r'^Flags:\s+0\s*$',
                r'^Rollback Index:\s+0\s*$', r'^\s+Partition Name:\s+' + re.escape(partition) + r'\s*$',
                r'^\s+Salt:\s+' + re.escape(salt) + r'\s*$',
                r'^\s+Image Size:\s+' + str(original) + r' bytes\s*$')
    if any(not re.search(pattern, text, re.MULTILINE) for pattern in expected):
        fail(f'Unexpected AVB descriptor: {path}')
    run('avbtool', 'verify_image', '--image', str(path))
    return {'footer_offset': capacity - 64, 'original_image_size': original,
            'vbmeta_offset': offset, 'vbmeta_size': size, 'algorithm': 'NONE',
            'self_verification': 'PASS', 'oem_authentication': 'NOT VERIFIED'}

def modinfo(path, field):
    return subprocess.check_output(['modinfo', '-F', field, str(path)], text=True).strip()

def normalized(name):
    return name.removesuffix('.ko').replace('-', '_')

def first_stage_closure(roots, info, names, builtin, by_name):
    pending, seen = list(roots), set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        for dep in info[name]['dependencies']:
            key = normalized(dep)
            if key in builtin:
                continue
            provider = by_name[key]
            if provider not in names:
                fail(f'First-stage dependency unavailable in vendor_boot: {name} -> {dep}')
            pending.append(provider)
    return sorted(seen)

def cpio(data):
    pos = 0
    result = []
    while pos + 110 <= len(data):
        start = pos
        header = data[pos:pos + 110]
        if header[:6] != b'070701':
            fail('Unsupported vendor ramdisk CPIO format')
        fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        pos += 110
        if namesize < 1 or pos + namesize > len(data) or data[pos + namesize - 1] != 0:
            fail('Invalid CPIO filename')
        name = data[pos:pos + namesize - 1].decode('utf-8')
        pos = (pos + namesize + 3) & ~3
        if pos + size > len(data):
            fail('Truncated CPIO payload')
        payload = data[pos:pos + size]
        pos = (pos + size + 3) & ~3
        result.append((name, header, payload, data[start:pos]))
        if name == 'TRAILER!!!':
            return result, data[pos:]
    fail('Missing CPIO trailer')

def source_modules(out):
    result = {}
    excluded = {'dlkm-staging', 'wlan-staging', 'avb-development'}
    for path in out.rglob('*.ko'):
        parts = path.relative_to(out).parts
        if (excluded.intersection(parts) or
            any(part.startswith('.wlan-check.') for part in parts[:-1]) or
            path.is_symlink()):
            continue
        if path.name in result:
            fail(f'Ambiguous native module filename: {path.name}: {result[path.name]} and {path}')
        result[path.name] = path
    return result

def verify_signature(path, cert, tmp):
    b = path.read_bytes()
    if not b.endswith(MAGIC):
        return False
    end = len(b) - len(MAGIC)
    if end < 12:
        fail(f'Invalid module signature: {path}')
    _, _, ident, _, _, _, size = struct.unpack('>BBBBB3sI', b[end-12:end])
    start = end - 12 - size
    if ident != 2 or size <= 0 or start < 0:
        fail(f'Invalid PKCS#7 trailer: {path}')
    signature = tmp / 'module-signature.der'
    payload = tmp / 'module-payload'
    signature.write_bytes(b[start:end-12])
    payload.write_bytes(b[:start])
    pem = tmp / 'certificate.pem'
    run('openssl', 'x509', '-inform', 'DER', '-in', str(cert), '-out', str(pem))
    signer = tmp / 'verified-signer.pem'
    result = subprocess.run(['openssl', 'cms', '-verify', '-binary', '-inform', 'DER',
                             '-in', str(signature), '-content', str(payload), '-certfile', str(pem),
                             '-noverify', '-signer', str(signer), '-out', '/dev/null'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        fail(f'Module signature verification failed: {path}: {result.stderr.decode(errors="replace").strip()}')
    verified = subprocess.check_output(['openssl', 'x509', '-in', str(signer), '-outform', 'DER'])
    if verified != cert.read_bytes():
        fail(f'Module signer does not match kernel certificate: {path}')
    return True

def parse_symbols(path):
    result = subprocess.run(['modprobe', '--show-exports', str(path)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        from elftools.elf.elffile import ELFFile
        with path.open('rb') as f:
            table = ELFFile(f).get_section_by_name('.symtab')
            if table is None or any(s.name.startswith('__ksymtab_') for s in table.iter_symbols()):
                fail(f'Cannot inspect module exports: {path}: {result.stderr.strip()}')
        return {}
    raw = result.stdout
    return {name: int(crc, 16) for crc, name in (line.split() for line in raw.splitlines() if line.strip())}

def runtime_elf(path):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    sections, relocations, symbols = {}, {}, []
    with path.open('rb') as f:
        elf = ELFFile(f)
        if elf['e_machine'] != 'EM_AARCH64' or elf['e_type'] != 'ET_REL':
            fail(f'Invalid module ELF format: {path}')
        for section in elf.iter_sections():
            name = section.name
            if name.startswith(('.debug_', '.zdebug_', '.rel.debug_', '.rela.debug_')):
                continue
            if isinstance(section, RelocationSection):
                table = elf.get_section(section['sh_link'])
                entries = []
                for rel in section.iter_relocations():
                    symbol = table.get_symbol(rel['r_info_sym'])
                    index = symbol['st_shndx']
                    target = elf.get_section(index).name if isinstance(index, int) and index < elf.num_sections() else str(index)
                    entries.append((rel['r_offset'], rel['r_info_type'], symbol.name,
                                    symbol['st_info']['type'], target,
                                    rel['r_addend'] if rel.is_RELA() else None))
                relocations[name] = entries
            elif section['sh_type'] == 'SHT_SYMTAB':
                for symbol in section.iter_symbols():
                    if symbol['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK'):
                        index = symbol['st_shndx']
                        target = elf.get_section(index).name if isinstance(index, int) and index < elf.num_sections() else str(index)
                        symbols.append((symbol.name, symbol['st_info']['bind'], symbol['st_info']['type'],
                                        target, symbol['st_value'], symbol['st_size']))
            elif name not in ('.strtab', '.shstrtab'):
                data = b'' if section['sh_type'] == 'SHT_NOBITS' else section.data()
                sections[name] = (section['sh_type'], section['sh_flags'], section['sh_size'],
                                  hashlib.sha256(data).hexdigest())
    return sections, relocations, sorted(symbols)

def verify_modules(out, native, names, stock_modules, stock, stage, tmp, fallback):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        fail('Python pyelftools is required to verify ELF providers')
    builtin = {normalized(Path(x).name) for x in (out / 'modules.builtin').read_text().splitlines() if x.endswith('.ko')}
    by_name = {normalized(n): n for n in native}
    if len(by_name) != len(native):
        fail('Native module names collide after normalization')
    partitions = {normalized(n): {'vendor_boot'} for n in names}
    for part in ('vendor_dlkm', 'system_dlkm'):
        root = stock / 'checking/modules' / part / 'lib/modules'
        if not root.is_dir():
            fail(f'Missing stock {part} inventory: {root}')
        for path in root.rglob('*.ko'):
            partitions.setdefault(normalized(path.name), set()).add(part)
    all_names = set(names)
    pending = list(names)
    while pending:
        name = pending.pop()
        for dep in filter(None, modinfo(native[name], 'depends').split(',')):
            key = normalized(dep)
            if key in builtin:
                continue
            if key not in by_name:
                provider = fallback.get(key)
                if provider is None:
                    fail(f'No native dependency artifact: {name} -> {dep}')
                filename, path = provider
                native[filename] = path
                by_name[key] = filename
            if key not in partitions:
                fail(f'Dependency has no verified stock partition: {name} -> {dep}')
            provider = by_name[key]
            if provider not in all_names:
                all_names.add(provider)
                pending.append(provider)
    info = {}
    symvers = {}
    paths = [out / 'Module.symvers'] + [p for p in (out / 'vendor').rglob('Module.symvers') if 'staging' not in str(p)]
    for name in all_names:
        path = native[name]
        while path != path.parent and path.name != 'native-build':
            path = path.parent
            candidate = path / 'Module.symvers'
            if candidate.is_file() and candidate not in paths:
                paths.append(candidate)
            if path == out:
                break
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            fields = line.split('\t')
            if len(fields) < 4:
                fail(f'Malformed symbol record: {path}')
            crc, name = fields[:2]
            namespace = fields[4] if len(fields) > 4 else ''
            entry = (int(crc, 16), namespace)
            if name in symvers and symvers[name] != entry:
                fail(f'Conflicting Module.symvers record: {name}')
            symvers[name] = entry
    build_sources = {name: str(native[name]) for name in all_names}
    cert = out / 'certs/signing_key.x509'
    for name in sorted(all_names - names):
        source = native[name]
        candidates = []
        for part in partitions[normalized(name)]:
            if part == 'vendor_boot':
                continue
            root = stage / part / 'lib/modules'
            matches = list(root.rglob(name)) if root.is_dir() else []
            if len(matches) != 1:
                fail(f'Cross-partition provider missing or ambiguous in {part} stage: {name}')
            provider = matches[0]
            if sha(provider) != sha(source) and runtime_elf(provider) != runtime_elf(source):
                fail(f'Cross-partition staged provider differs from native build: {part}: {name}')
            candidates.append(provider)
        if not candidates:
            fail(f'Cross-partition provider has no staged partition: {name}')
        if len({sha(path) for path in candidates}) != 1:
            fail(f'Cross-partition provider copies differ: {name}')
        native[name] = candidates[0]
    kernel_exports = {}
    protected_text = (out / 'include/generated/gki_module_protected_exports.h').read_text()
    allowed_text = (out / 'include/generated/gki_module_unprotected.h').read_text()
    protected = set(re.findall(r'"([^\"]+)"', protected_text))
    allowed = set(re.findall(r'"([^\"]+)"', allowed_text))
    if not protected or not allowed:
        fail('Missing generated GKI symbol protection lists')
    with (out / 'vmlinux').open('rb') as f:
        elf = ELFFile(f)
        table = elf.get_section_by_name('.symtab')
        if not table:
            fail('Missing vmlinux symbol table')
        cert_bounds = {}
        linked_lists = {}
        for symbol in table.iter_symbols():
            if symbol.name in ('__cert_list_start', '__cert_list_end'):
                cert_bounds[symbol.name] = symbol
            if symbol.name in ('gki_protected_exports_symbols', 'gki_unprotected_symbols'):
                linked_lists[symbol.name] = symbol
            if not symbol.name.startswith('__crc_'):
                continue
            section_index = symbol['st_shndx']
            if section_index == 'SHN_ABS':
                kernel_exports[symbol.name[6:]] = symbol['st_value']
            elif isinstance(section_index, int):
                section = elf.get_section(section_index)
                offset = symbol['st_value'] - section['sh_addr']
                if section['sh_type'] != 'SHT_NOBITS' and 0 <= offset <= section.data_size - 4:
                    kernel_exports[symbol.name[6:]] = struct.unpack_from('<I', section.data(), offset)[0]
        if set(cert_bounds) != {'__cert_list_start', '__cert_list_end'}:
            fail('Cannot locate built-in certificate list')
        start, end = cert_bounds['__cert_list_start'], cert_bounds['__cert_list_end']
        if start['st_shndx'] != end['st_shndx']:
            fail('Invalid built-in certificate list')
        section = elf.get_section(start['st_shndx'])
        first = start['st_value'] - section['sh_addr']
        certificates = section.data()[first:first + end['st_value'] - start['st_value']]
        if cert.read_bytes() not in certificates:
            fail('Configured module certificate is not in the vmlinux trusted certificate list')
        for key, text, macro, expected in (
            ('gki_protected_exports_symbols', protected_text, 'MAX_PROTECTED_EXPORTS_NAME_LEN', protected),
            ('gki_unprotected_symbols', allowed_text, 'MAX_UNPROTECTED_NAME_LEN', allowed),
        ):
            match = re.search(r'#define\s+' + macro + r'\s+\((\d+)\)', text)
            if key not in linked_lists or not match:
                fail(f'Cannot verify linked GKI list: {key}')
            width = int(match.group(1))
            symbol = linked_lists[key]
            section = elf.get_section(symbol['st_shndx'])
            offset = symbol['st_value'] - section['sh_addr']
            raw = section.data()[offset:offset + symbol['st_size']]
            if len(raw) % width:
                fail(f'Invalid linked GKI list: {key}')
            actual = {raw[i:i+width].split(b'\0', 1)[0].decode() for i in range(0, len(raw), width)}
            if actual != expected:
                fail(f'Generated and linked GKI lists differ: {key}')
    for name in sorted(all_names):
        path = native[name]
        with path.open('rb') as f:
            elf = ELFFile(f)
            if elf['e_machine'] != 'EM_AARCH64' or elf['e_type'] != 'ET_REL':
                fail(f'Invalid module ELF format: {path}')
        actual_name = modinfo(path, 'name')
        if normalized(name) != normalized(actual_name):
            fail(f'Module identity mismatch: {path}: {actual_name}')
        vm = modinfo(path, 'vermagic')
        if not (vm.startswith(RELEASE + ' ') and ' modversions ' in vm and vm.endswith(' aarch64')):
            fail(f'Invalid vermagic: {path}: {vm}')
        deps = [x for x in modinfo(path, 'depends').split(',') if x]
        imports = subprocess.check_output(['modprobe', '--dump-modversions', str(path)], text=True).splitlines()
        if not imports:
            fail(f'Missing module symbol versions: {path}')
        versions = {symbol: int(crc, 16) for crc, symbol in (line.split() for line in imports)}
        namespaces = set(modinfo(path, 'import_ns').splitlines())
        signed = verify_signature(path, cert, tmp)
        exports = parse_symbols(path)
        if not signed and protected.intersection(exports):
            fail(f'Unsigned module exports protected symbols: {name}')
        for symbol, crc in versions.items():
            if symbol not in symvers or symvers[symbol][0] != crc:
                fail(f'Missing or mismatched symbol CRC: {name}: {symbol}')
            ns = symvers[symbol][1]
            if ns and ns not in namespaces:
                fail(f'Missing namespace: {name}: {symbol}: {ns}')
        info[name] = {'source': str(path), 'native_build_artifact': build_sources[name],
                      'sha256': sha(path), 'module_name': actual_name,
                      'vermagic': vm, 'dependencies': deps, 'signed': signed,
                      'versions': versions, 'exports': exports}
    exports = {}
    for name, row in info.items():
        for sym, crc in row['exports'].items():
            if sym in exports or sym in kernel_exports:
                fail(f'Duplicate kernel or module export: {sym}')
            exports[sym] = (name, crc, row['signed'])
    for name, row in info.items():
        for sym, crc in row['versions'].items():
            if sym in exports:
                provider, actual_crc, signed = exports[sym]
                if crc != actual_crc:
                    fail(f'Provider CRC mismatch: {name}: {sym}: {provider}')
                if not row['signed'] and signed and sym not in allowed:
                    fail(f'Unsigned consumer cannot access signed provider: {name}: {sym}: {provider}')
            elif kernel_exports.get(sym) != crc:
                fail(f'No actual kernel or vendor_boot provider with matching CRC: {name}: {sym}')
    depfile = stock_modules.get('lib/modules/modules.dep')
    aliases = stock_modules.get('lib/modules/modules.alias')
    if depfile is None or aliases is None:
        fail('Missing stock vendor ramdisk module metadata')
    stock_deps = {}
    for line in depfile.decode().splitlines():
        left, sep, right = line.partition(':')
        if not sep:
            fail('Malformed stock modules.dep')
        stock_deps[normalized(Path(left).name)] = {normalized(Path(x).name) for x in right.split()}
    alias_lines = set(aliases.decode().splitlines())
    early_roots = set()
    for listing in ('modules.load', 'modules.load.recovery'):
        content = stock_modules.get('lib/modules/' + listing)
        if content is None:
            fail(f'Missing stock {listing}')
        for line in content.decode().splitlines():
            name = line.strip()
            if name and not name.startswith('#') and Path(name).name not in names:
                fail(f'Stock {listing} references an unavailable module: {name}')
            if name and not name.startswith('#'):
                early_roots.add(Path(name).name)
    early = first_stage_closure(early_roots, info, names, builtin, by_name)
    for name in sorted(names):
        row = info[name]
        deps = {normalized(d) for d in row['dependencies'] if normalized(d) not in builtin and by_name[normalized(d)] in names}
        if normalized(name) not in stock_deps or not deps.issubset(stock_deps[normalized(name)]):
            fail(f'Stock modules.dep does not cover native dependencies: {name}')
        for alias in modinfo(native[name], 'alias').splitlines():
            if alias and f'alias {alias} {row["module_name"]}' not in alias_lines:
                fail(f'Stock modules.alias does not cover native alias: {name}: {alias}')
    external = {name: sorted(partitions[normalized(name)]) for name in info if name not in names}
    return info, external, early

def main():
    ap = argparse.ArgumentParser()
    for opt in ('out', 'build', 'stock', 'boot', 'image-sha256', 'dlkm-stage'):
        ap.add_argument('--' + opt, required=True)
    args = ap.parse_args()
    out, build, stock, boot, stage = map(Path, (args.out, args.build, args.stock, args.boot, args.dlkm_stage))
    image = out / 'arch/arm64/boot/Image'
    for p in (image, out/'Module.symvers', out/'modules.builtin', out/'vmlinux', boot, stock/'boot.img', stock/'vendor_boot.img'):
        if not p.is_file():
            fail(f'Missing packaging input: {p}')
    if sha(image) != args.image_sha256 or sha(stock/'boot.img') != STOCK_BOOT or sha(stock/'vendor_boot.img') != STOCK_VENDOR_BOOT:
        fail('Kernel or stock image provenance mismatch')
    # Use the pinned stock ramdisk for inventory.
    stockdir = stock/'checking/ramdisks/vendor_boot/lib/modules'
    if not stockdir.is_dir():
        fail(f'Missing stock vendor-boot inventory: {stockdir}')
    names = {p.name for p in stockdir.glob('*.ko')}
    if len(names) != 282:
        fail(f'Unexpected stock vendor_boot inventory count: {len(names)}')
    native = source_modules(out)
    missing = sorted(names - native.keys())
    fallback = {}
    if missing:
        rc0 = build/'weary-stars-rc0/rc0-manifest.json'
        old = build/'ctwo-partition-mirror/native-build'
        if not rc0.is_file() or sha(rc0) != RC0_MANIFEST_SHA256:
            fail('RC0 manifest missing or changed; cannot consider older native artifacts')
        for filename in ('.config', 'Module.symvers'):
            if not (old/filename).is_file() or sha(old/filename) != sha(out/filename):
                fail(f'RC0 {filename} differs from current build; cannot consider older native artifacts')
        records = json.loads(rc0.read_text())['modules']
        for record in records:
            path = Path(record['build_artifact'])
            if path.is_relative_to(old) and path.is_file() and not path.is_symlink():
                fallback[normalized(record['name'])] = (record['name'], path, record['sha256'])
        for name in missing:
            candidate = fallback.get(normalized(name))
            if candidate and candidate[0] == name and sha(candidate[1]) == candidate[2]:
                native[name] = candidate[1]
                print(f'Using hash-pinned RC0 native candidate pending current-kernel validation: {name}: {candidate[1]}', flush=True)
        # Check fallback hashes before use.
        fallback = {key: (filename, path) for key, (filename, path, digest) in fallback.items()
                    if sha(path) == digest}
        missing = sorted(names - native.keys())
    if missing:
        fail(f'Missing {len(missing)} native vendor_boot modules: ' + ', '.join(missing))
    def capacity(name, expected):
        value = os.environ.get(name, str(expected))
        if not value.isdecimal() or int(value) != expected:
            fail(f'{name} must equal the verified active-slot size {expected}')
        return int(value)
    boot_capacity = capacity('CTWO_BOOT_PARTITION_BYTES', BOOT_CAPACITY)
    vendor_capacity = capacity('CTWO_VENDOR_BOOT_PARTITION_BYTES', VENDOR_BOOT_CAPACITY)
    destroot = build/'boot-pairs'; dest = destroot/args.image_sha256
    destroot.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        fail(f'Refusing to overwrite immutable output: {dest}')
    with tempfile.TemporaryDirectory(prefix='.ctwo-pair-', dir=destroot) as t:
        tmp = Path(t); extracted = tmp/'stock'; extracted.mkdir()
        stock_info = subprocess.check_output(['unpack_bootimg','--boot_img',str(stock/'vendor_boot.img'),'--out',str(extracted)], text=True)
        if 'vendor boot image header version: 4' not in stock_info or stock_info.count('vendor_ramdisk00:') != 1 or 'type: 0x1' not in stock_info:
            fail('Unsupported vendor_boot fragment layout')
        raw = subprocess.check_output(['lz4','-d','-c',str(extracted/'vendor_ramdisk00')])
        old, tail = cpio(raw)
        stock_modules = {n:d for n,_,d,_ in old}
        if len(stock_modules) != len(old):
            fail('Duplicate stock ramdisk entries are unsupported')
        archive_names = {Path(n).name for n in stock_modules if n.startswith('lib/modules/') and n.endswith('.ko')}
        if archive_names != names:
            fail('Extracted stock inventory disagrees with original ramdisk')
        info, external, early = verify_modules(out, native, names, stock_modules, stock, stage, tmp, fallback)
        data = bytearray()
        for name, header, payload, record in old:
            if name.startswith('lib/modules/') and name.endswith('.ko'):
                n = Path(name).name
                if name != 'lib/modules/' + n:
                    fail(f'Unsupported vendor module path: {name}')
                payload = native[n].read_bytes()
                h = bytearray(header);h[54:62] = f'{len(payload):08x}'.encode()
                namelen = int(header[94:102], 16)
                record = bytes(h) + record[110:110+namelen]
                record += b'\0' * (-len(record) % 4);record += payload;record += b'\0' * (-len(record) % 4)
            data += record
        data += tail
        ramdisk = tmp/'ramdisk.cpio';ramdisk.write_bytes(data)
        compressed = tmp/'ramdisk.lz4';run('lz4','-l','-9','-f','-q',str(ramdisk),str(compressed))
        candidate = tmp/'candidate';candidate.mkdir()
        shutil.copyfile(boot, candidate/'boot.img')
        boot_avb = verify_avb(candidate/'boot.img', boot_capacity, 'boot',
                              'baef919029f01159aaf488a149e4b95800e43a5733d30bbe349e2acfe70644eb')
        checkboot=tmp/'check-boot';checkboot.mkdir()
        bootinfo=subprocess.check_output(['unpack_bootimg','--boot_img',str(candidate/'boot.img'),'--out',str(checkboot)],text=True)
        if 'boot image header version: 4' not in bootinfo or sha(checkboot/'kernel') != args.image_sha256:
            fail('Candidate boot image does not contain the current kernel')
        with (stock/'boot.img').open('rb') as f:
            stock_header = bytearray(f.read(4096))
        with (candidate/'boot.img').open('rb') as f:
            boot_header = bytearray(f.read(4096))
        stock_header[8:12] = boot_header[8:12] = b'\0' * 4
        if stock_header != boot_header:
            fail('Boot header differs from stock outside kernel size')
        cmdline='video=vfb:640x400,bpp=32,memsize=3072000 nosoftlockup pstore.compress=none page_pinner=on printk.devkmsg=on mem.enable_mglru=1 bootconfig'
        run('mkbootimg','--header_version','4','--pagesize','4096','--base','0','--kernel_offset','0x8000','--ramdisk_offset','0x01000000','--tags_offset','0x100','--dtb_offset','0x01f00000','--vendor_cmdline',cmdline,'--board','','--dtb',str(extracted/'dtb'),'--vendor_bootconfig',str(extracted/'bootconfig'),'--ramdisk_type','platform','--ramdisk_name','','--vendor_ramdisk_fragment',str(compressed),'--vendor_boot',str(candidate/'vendor_boot.img'))
        if (candidate/'vendor_boot.img').stat().st_size > vendor_capacity:
            fail('vendor_boot.img exceeds verified physical partition size')
        run('avbtool', 'add_hash_footer', '--image', str(candidate/'vendor_boot.img'),
            '--partition_size', str(vendor_capacity), '--partition_name', 'vendor_boot',
            '--hash_algorithm', 'sha256', '--salt',
            '38f2a31e313119c8f6d991d2e4d0768380edcb73a19e7d2bfd7bfa73672dcd91',
            '--algorithm', 'NONE', '--rollback_index', '0', '--flags', '0',
            '--prop', 'com.android.build.vendor_boot.fingerprint:motorola/ctwo/ctwo:14/UUV3S4HV-W1-ST14/cb805:user/release-keys')
        vendor_avb = verify_avb(candidate/'vendor_boot.img', vendor_capacity, 'vendor_boot',
                                '38f2a31e313119c8f6d991d2e4d0768380edcb73a19e7d2bfd7bfa73672dcd91')
        check = tmp/'check-vendor';check.mkdir()
        check_info=subprocess.check_output(['unpack_bootimg','--boot_img',str(candidate/'vendor_boot.img'),'--out',str(check)],text=True)
        norm=lambda x:[v for v in x.splitlines() if not v.strip().startswith(('vendor ramdisk total size:', 'size:'))]
        if norm(stock_info)!=norm(check_info) or (check/'dtb').read_bytes()!=(extracted/'dtb').read_bytes() or (check/'bootconfig').read_bytes()!=(extracted/'bootconfig').read_bytes():
            fail('Vendor boot header, DTB or bootconfig changed')
        final, final_tail=cpio(subprocess.check_output(['lz4','-d','-c',str(check/'vendor_ramdisk00')]))
        if len(final)!=len(old) or tail!=final_tail:
            fail('Vendor ramdisk entry count or trailer changed')
        preserved_records = {}
        for (n,h,d,r),(nn,hh,dd,rr) in zip(old,final):
            if n!=nn:fail('Vendor ramdisk entry order changed')
            if n.startswith('lib/modules/') and n.endswith('.ko'):
                if h[:54]!=hh[:54] or h[62:]!=hh[62:] or hashlib.sha256(dd).hexdigest()!=info[Path(n).name]['sha256']:
                    fail(f'Native module or metadata mismatch: {n}')
            elif r!=rr:
                fail(f'Non-module ramdisk entry changed: {n}')
            else:
                preserved_records[n] = {'record_sha256':hashlib.sha256(r).hexdigest(),
                                        'payload_sha256':hashlib.sha256(d).hexdigest()}
        stock_descriptors = {
            'boot.img': ('baef919029f01159aaf488a149e4b95800e43a5733d30bbe349e2acfe70644eb',
                         35586048, '1b57aed3216f764b1f0cb9f1d897317eb22fbe846b98b705d25118a52aa633ed'),
            'vendor_boot.img': ('38f2a31e313119c8f6d991d2e4d0768380edcb73a19e7d2bfd7bfa73672dcd91',
                                8654848, 'c5d7b47f9b4b54a0e12e68174837e23d43e4fb18a2c230f8677d79ee9901c67b'),
        }
        for filename, (salt, length, expected) in stock_descriptors.items():
            with (candidate/filename).open('rb') as f:
                digest = hashlib.sha256(bytes.fromhex(salt) + f.read(length)).hexdigest()
            if digest == expected:
                fail(f'Unexpectedly matches stock root descriptor: {filename}')
        provider_dir = candidate/'provenance/providers'
        provider_dir.mkdir(parents=True)
        for name in sorted(external):
            provider = provider_dir/name
            shutil.copyfile(native[name], provider)
            if sha(provider) != info[name]['sha256']:
                fail(f'Cross-partition provider changed during packaging: {name}')
            info[name]['validated_stage_source'] = info[name]['source']
            info[name]['source'] = str(provider.relative_to(candidate))
        manifest={'kernel_release':RELEASE,'kernel_image':str(image),'kernel_sha256':args.image_sha256,
                  'vmlinux':str(out/'vmlinux'),'vmlinux_sha256':sha(out/'vmlinux'),
                  'config':str(out/'.config'),'config_sha256':sha(out/'.config'),
                  'module_symvers':str(out/'Module.symvers'),'module_symvers_sha256':sha(out/'Module.symvers'),
                  'stock_boot':str(stock/'boot.img'),'stock_boot_sha256':STOCK_BOOT,
                  'stock_vendor_boot':str(stock/'vendor_boot.img'),'stock_vendor_boot_sha256':STOCK_VENDOR_BOOT,
                  'partition_capacities':{'boot':boot_capacity,'vendor_boot':vendor_capacity},
                  'images':{n:{'sha256':sha(candidate/n),'size':(candidate/n).stat().st_size} for n in ('boot.img','vendor_boot.img')},
                  'modules':info,'external_dependency_partitions':external,
                  'first_stage_dependency_closure':early,
                  'vendor_ramdisk_fragment':{'name':'','type':'platform','board_id':[0]*16,
                                             'compression':'lz4 legacy','stock_fragment_sha256':sha(extracted/'vendor_ramdisk00'),
                                             'candidate_fragment_sha256':sha(check/'vendor_ramdisk00')},
                  'preserved_components':{'stock_vendor_boot_dtb_sha256':sha(extracted/'dtb'),
                                          'candidate_vendor_boot_dtb_sha256':sha(check/'dtb'),
                                          'stock_bootconfig_sha256':sha(extracted/'bootconfig'),
                                          'candidate_bootconfig_sha256':sha(check/'bootconfig'),
                                          'nonmodule_cpio_records':preserved_records},
                  'modified_components':['boot kernel and size; stock signed post-kernel structures omitted',
                                         'vendor ramdisk module data, compressed stream and affected offsets',
                                         'development AVB footers'],
                  'avb':{'boot':boot_avb,'vendor_boot':vendor_avb,
                         'stock_root_authentication':'NO: unchanged root vbmeta authenticates stock payloads'},
                  'dependency_validation':'PASS for audited native/staged artifacts; future deployment must use the exact recorded cross-partition provider hashes; runtime load order is unverified',
                  'packaging_status':'PASS: structural packaging only; first device test NO-GO until OEM/development AVB trust, cross-partition runtime loading and rollback are separately validated'}
        (candidate/'manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
        libc = ctypes.CDLL(None, use_errno=True)
        if not hasattr(libc, 'renameat2'):
            fail('Atomic no-overwrite publication is unavailable')
        if libc.renameat2(-100, os.fsencode(candidate), -100, os.fsencode(dest), 1) != 0:
            error = ctypes.get_errno()
            fail(f'Atomic no-overwrite publication failed: {os.strerror(error)}')
    print('[ok] boot.img')
    print('[ok] vendor_boot.img')
    print('Development boot pair: OEM authentication is unverified.')

if __name__ == '__main__':
    main()

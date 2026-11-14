#!/usr/bin/env python3
"""Reject a system_dlkm release when native staging is incomplete."""
import argparse
import csv
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import struct

RELEASE = '6.1.128—WearyStars⭐'
STOCK_SHA256 = 'fa2577c5e78655a73cfbf74b3338bfb3cdee46d035f9ec34fba68ca4cdfabb99'
CAPACITY = 11849728
RC0_SHA256 = 'f50f7d6cd636428c2b68d4e1fec72577df47e7ba88ec0b19aa964975e5bb8753'
IMPORT_AUDIT_SHA256 = '701d600a35d9667630e47d079e960df3b6a226ff57af1b7db307a3bb93fa859d'

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1048576), b''):
            h.update(data)
    return h.hexdigest()

def modinfo(path, field):
    return subprocess.check_output(['modinfo', '-F', field, str(path)], text=True).strip()

def key(name):
    return name.removesuffix('.ko').replace('-', '_')

def verify_known_vendor_consumers(out, build, records, sources, helper):
    """Validate existing RC0 Bluetooth/swap binaries against this kernel's providers."""
    old = build/'ctwo-partition-mirror/native-build'
    for filename in ('.config', 'Module.symvers'):
        if digest(old/filename) != digest(out/filename):
            raise SystemExit(f'RC0/current {filename} differs; cannot reuse vendor modules')
    audit = build/'ctwo-partition-mirror/reports/symbol-imports.csv'
    if digest(audit) != IMPORT_AUDIT_SHA256:
        raise SystemExit('Frozen symbol-provider evidence changed')
    image_sha = digest(out/'arch/arm64/boot/Image')
    pair = build/'boot-pairs'/image_sha
    pair_manifest = json.loads((pair/'manifest.json').read_text())
    if pair_manifest['kernel_sha256'] != image_sha:
        raise SystemExit('Boot-pair baseline does not match current Image')
    for name in ('boot.img','vendor_boot.img'):
        if digest(pair/name) != pair_manifest['images'][name]['sha256']:
            raise SystemExit(f'Boot-pair artifact changed: {name}')
    audit_rows = {}
    with audit.open(newline='') as f:
        for row in csv.DictReader(f):
            if row['module'] in ('btpower.ko','moto_swap.ko'):
                if row['status'] != 'PASS' or ';' in row['actual_binary_providers']:
                    raise SystemExit(f"Unresolved or ambiguous historical provider: {row['module']} {row['symbol']}")
                audit_rows.setdefault(row['module'], {})[row['symbol']] = row
    current_symvers = {}
    for line in (out/'Module.symvers').read_text().splitlines():
        f = line.split('\t')
        if len(f) >= 4:
            current_symvers[f[1]] = (int(f[0],16), f[2], f[4] if len(f)>4 else '')
    needed = {symbol for rows in audit_rows.values() for symbol,row in rows.items()
              if row['actual_binary_providers'].startswith('vmlinux:')}
    from elftools.elf.elffile import ELFFile
    kernel_crc, sections, linked_lists = {}, {}, {}
    with (out/'vmlinux').open('rb') as f:
        elf=ELFFile(f);table=elf.get_section_by_name('.symtab')
        if table is None:
            raise SystemExit('Native vmlinux symbol table missing')
        for symbol in table.iter_symbols():
            name=symbol.name
            if name in ('gki_unprotected_symbols','gki_protected_exports_symbols'):
                linked_lists[name]=symbol
            if not name.startswith('__crc_') or name[6:] not in needed:
                continue
            index=symbol['st_shndx']
            if index=='SHN_ABS':
                kernel_crc[name[6:]]=symbol['st_value'];continue
            if isinstance(index,int):
                sec=elf.get_section(index);offset=symbol['st_value']-sec['sh_addr']
                if sec['sh_type']!='SHT_NOBITS' and 0 <= offset <= sec.data_size-4:
                    if index not in sections:
                        sections[index]=sec.data()
                    kernel_crc[name[6:]]=struct.unpack_from('<I',sections[index],offset)[0]
        for symbol_name,header_name,macro in (
            ('gki_unprotected_symbols','gki_module_unprotected.h','MAX_UNPROTECTED_NAME_LEN'),
            ('gki_protected_exports_symbols','gki_module_protected_exports.h','MAX_PROTECTED_EXPORTS_NAME_LEN')):
            text=(out/'include/generated'/header_name).read_text()
            match=re.search(r'#define\s+'+macro+r'\s+\((\d+)\)',text)
            if symbol_name not in linked_lists or not match:
                raise SystemExit(f'Cannot verify linked GKI list: {symbol_name}')
            s=linked_lists[symbol_name];sec=elf.get_section(s['st_shndx']);offset=s['st_value']-sec['sh_addr'];width=int(match.group(1))
            raw=sec.data()[offset:offset+s['st_size']]
            actual={raw[i:i+width].split(b'\0',1)[0].decode() for i in range(0,len(raw),width)}
            if len(raw)%width or actual!=set(re.findall(r'"([^\"]+)"',text)):
                raise SystemExit(f'Linked and generated GKI lists differ: {symbol_name}')
    provider_paths={}
    for name in ('rfkill.ko','zsmalloc.ko'):
        paths=sources.get(name,[])
        if len(paths)!=1:raise SystemExit(f'Native provider missing or ambiguous: {name}')
        provider_paths[name]=paths[0]
    for name in ('smcinvoke_dlkm.ko','pinctrl-msm.ko'):
        row=pair_manifest['modules'][name];path=Path(row['source'])
        if not path.is_file() or digest(path)!=row['sha256']:
            raise SystemExit(f'Boot-pair provider changed: {name}')
        provider_paths[name]=path
    exports={name:helper['parse_symbols'](path) for name,path in provider_paths.items()}
    namespaces={}
    symbol_files=[out/'Module.symvers']
    for path in provider_paths.values():
        cur=path.parent
        while cur != cur.parent:
            candidate=cur/'Module.symvers'
            if candidate.is_file() and candidate not in symbol_files:symbol_files.append(candidate)
            if cur in (out,old):break
            cur=cur.parent
    for path in symbol_files:
        for line in path.read_text().splitlines():
            f=line.split('\t')
            if len(f)>=4:
                item=(int(f[0],16),f[4] if len(f)>4 else '')
                if f[1] in namespaces and namespaces[f[1]]!=item:
                    raise SystemExit(f'Conflicting symbol namespace/CRC: {f[1]}')
                namespaces[f[1]]=item
    allowed=set(re.findall(r'"([^\"]+)"',(out/'include/generated/gki_module_unprotected.h').read_text()))
    protected=set(re.findall(r'"([^\"]+)"',(out/'include/generated/gki_module_protected_exports.h').read_text()))
    if not allowed:raise SystemExit('GKI symbol allowlist missing')
    result={}
    for name in ('btpower.ko','moto_swap.ko'):
        record=next((x for x in records if x['name']==name),None)
        if record is None:raise SystemExit(f'RC0 inventory missing {name}')
        path=Path(record['build_artifact'])
        if not path.is_relative_to(old) or not path.is_file() or digest(path)!=record['sha256']:
            raise SystemExit(f'RC0 native artifact missing or modified: {name}')
        if not modinfo(path,'vermagic').startswith(RELEASE+' '):
            raise SystemExit(f'Native vermagic mismatch: {name}')
        with path.open('rb') as f:
            f.seek(-len(b'~Module signature appended~\n'), os.SEEK_END)
            if f.read()==b'~Module signature appended~\n':
                raise SystemExit(f'Unexpected signed RC0 consumer; signer requires verification: {name}')
        if protected.intersection(helper['parse_symbols'](path)):
            raise SystemExit(f'Unsigned native consumer exports protected symbols: {name}')
        imports={symbol:int(crc,16) for crc,symbol in (line.split() for line in
                 subprocess.check_output(['modprobe','--dump-modversions',str(path)],text=True).splitlines())}
        if set(imports)!=set(audit_rows.get(name,{})):
            raise SystemExit(f'Frozen import list differs: {name}')
        imported_ns=set(modinfo(path,'import_ns').splitlines())
        for symbol,crc in imports.items():
            row=audit_rows[name][symbol]; provider, oldcrc=row['actual_binary_providers'].rsplit(':',1)
            if crc!=int(oldcrc,16):raise SystemExit(f'Frozen CRC differs: {name}: {symbol}')
            if provider=='vmlinux':
                if kernel_crc.get(symbol)!=crc:raise SystemExit(f'Native vmlinux CRC differs: {name}: {symbol}')
            elif exports.get(provider,{}).get(symbol)!=crc:
                raise SystemExit(f'Native provider CRC differs: {name}: {symbol}: {provider}')
            if symbol not in namespaces or namespaces[symbol][0]!=crc:
                raise SystemExit(f'Module.symvers missing or differing: {name}: {symbol}')
            namespace=namespaces[symbol][1]
            if namespace and namespace not in imported_ns:
                raise SystemExit(f'Missing namespace: {name}: {symbol}: {namespace}')
            if provider=='rfkill.ko' and symbol not in allowed:
                raise SystemExit(f'Unsigned {name} cannot import signed rfkill symbol {symbol}')
        result[name]={'source':str(path),'sha256':digest(path),'vermagic':modinfo(path,'vermagic'),
                      'dependencies':modinfo(path,'depends').split(','),'verified_imports':len(imports),
                      'status':'STATICALLY VERIFIED; NOT STAGED OR RUNTIME TESTED'}
    return result

def main():
    ap = argparse.ArgumentParser()
    for name in ('out', 'build', 'stock', 'dlkm-stage', 'image-sha256'):
        ap.add_argument('--' + name, required=True)
    args = ap.parse_args()
    out, build, stock, stage = map(Path, (args.out, args.build, args.stock, args.dlkm_stage))
    image = out/'arch/arm64/boot/Image'
    rc0 = build/'weary-stars-rc0/rc0-manifest.json'
    stock_img = stock/'checking/modules/logical-images/system_dlkm_a.img'
    if digest(image) != args.image_sha256 or digest(rc0) != RC0_SHA256 or digest(stock_img) != STOCK_SHA256:
        raise SystemExit('System DLKM input provenance mismatch')
    evidence = Path.home()/'Documents/ctwo/logs/ctwo-fastbootd-20261108_093808.txt'
    if 'partition-size:system_dlkm_a: 0xB4D000' not in evidence.read_text():
        raise SystemExit('Missing independent system_dlkm_a capacity evidence')
    specified = os.environ.get('CTWO_SYSTEM_DLKM_PARTITION_BYTES', str(CAPACITY))
    if not specified.isdecimal() or int(specified) != CAPACITY:
        raise SystemExit('CTWO_SYSTEM_DLKM_PARTITION_BYTES must match the verified active-slot capacity')
    manifest = json.loads(rc0.read_text())
    records = [x for x in manifest['modules'] if 'system_dlkm' in x['partitions']]
    if len(records) != 60 or len({x['name'] for x in records}) != 60:
        raise SystemExit('Unexpected stock system_dlkm inventory')
    sources = {}
    for path in out.rglob('*.ko'):
        if {'wlan-staging', 'dlkm-staging'}.intersection(path.relative_to(out).parts) or path.is_symlink():
            continue
        sources.setdefault(path.name, []).append(path)
    sysstage = stage/'system_dlkm/lib/modules'/RELEASE
    vendorstage = stage/'vendor_dlkm/lib/modules'
    if not sysstage.is_dir() or not vendorstage.is_dir():
        raise SystemExit('Missing system or vendor DLKM stage')
    helper = runpy.run_path(str(Path(__file__).with_name('ctwo-package-boot.py')), run_name='ctwo_helpers')
    vendor_candidates = verify_known_vendor_consumers(out, build, manifest['modules'], sources, helper)
    symvers = {}
    for line in (out/'Module.symvers').read_text().splitlines():
        fields = line.split('\t')
        if len(fields) < 4:
            raise SystemExit('Malformed native Module.symvers')
        symvers[fields[1]] = (int(fields[0], 16), fields[4] if len(fields) > 4 else '')
    results, errors = [], []
    by_name = {}
    for record in records:
        name = record['name']
        current = sources.get(name, [])
        found = list(sysstage.rglob(name))
        row = {'name': name, 'native_candidates': [str(p) for p in current],
               'stage_paths': [str(p) for p in found], 'status': 'BLOCKED'}
        if len(current) != 1 or len(found) != 1:
            errors.append(f'{name}: expected one native source and one staged copy')
            results.append(row); continue
        source, staged = current[0], found[0]
        row.update({'native_sha256': digest(source), 'staged_sha256': digest(staged),
                    'stock_sha256': record['partitions']['system_dlkm']['stock_sha256'],
                    'native_vermagic': modinfo(source, 'vermagic'), 'staged_vermagic': modinfo(staged, 'vermagic')})
        if not row['native_vermagic'].startswith(RELEASE+' ') or ' modversions ' not in row['native_vermagic']:
            errors.append(f'{name}: native vermagic mismatch')
        imports = subprocess.check_output(['modprobe', '--dump-modversions', str(source)], text=True).splitlines()
        ns = set(modinfo(source, 'import_ns').splitlines())
        row['imports'] = len(imports)
        if not imports:
            errors.append(f'{name}: missing versioned imports')
        for line in imports:
            crc, symbol = line.split()
            entry = symvers.get(symbol)
            if not entry or entry[0] != int(crc, 16) or (entry[1] and entry[1] not in ns):
                errors.append(f'{name}: missing CRC or namespace for {symbol}')
        if row['staged_sha256'] == row['stock_sha256']:
            row['status'] = 'STOCK_6.1.145'
            errors.append(f'{name}: stock binary remains in system_dlkm stage')
        elif helper['runtime_elf'](source) != helper['runtime_elf'](staged):
            row['status'] = 'NATIVE_MISMATCH'
            errors.append(f'{name}: stage differs from native ELF')
        else:
            row['status'] = 'NATIVE_ELF_MATCH; SIGNATURE AND CROSS-PARTITION POLICY NOT YET VERIFIED'
        by_name[key(name)] = name
        results.append(row)
    stock_count = sum(x['status'] == 'STOCK_6.1.145' for x in results)
    # Build an isolated native stage; never change the supplied mixed stock stage.
    candidate_result = {'status': 'NOT PREPARED'}
    if len(by_name) == 60 and not any('native vermagic mismatch' in x or 'missing CRC or namespace' in x for x in errors):
        protected = set(re.findall(r'"([^\"]+)"', (out/'include/generated/gki_module_protected_exports.h').read_text()))
        allowed = set(re.findall(r'"([^\"]+)"', (out/'include/generated/gki_module_unprotected.h').read_text()))
        if not protected or not allowed:
            raise SystemExit('Missing GKI protection lists')
        cert, private = out/'certs/signing_key.x509', out/'certs/signing_key.pem'
        if not cert.is_file() or not private.is_file():
            raise SystemExit('Existing module signing identity is incomplete')
        pub = subprocess.check_output(['openssl','pkey','-in',str(private),'-pubout','-outform','DER'])
        cpem = subprocess.check_output(['openssl','x509','-inform','DER','-in',str(cert),'-pubkey','-noout'])
        certpub = subprocess.run(['openssl','pkey','-pubin','-outform','DER'], input=cpem, stdout=subprocess.PIPE, check=True).stdout
        if pub != certpub:
            raise SystemExit('Existing module key and certificate differ')
        from elftools.elf.elffile import ELFFile
        with (out/'vmlinux').open('rb') as f:
            elf = ELFFile(f); table = elf.get_section_by_name('.symtab')
            bounds = {s.name:s for s in table.iter_symbols() if s.name in ('__cert_list_start','__cert_list_end')}
            if set(bounds) != {'__cert_list_start','__cert_list_end'}:
                raise SystemExit('Cannot locate native trusted certificate list')
            first,last = bounds['__cert_list_start'],bounds['__cert_list_end']
            if first['st_shndx'] != last['st_shndx']:
                raise SystemExit('Invalid native trusted certificate list')
            sec=elf.get_section(first['st_shndx']);off=first['st_value']-sec['sh_addr']
            if cert.read_bytes() not in sec.data()[off:off+last['st_value']-first['st_value']]:
                raise SystemExit('Module signing certificate is not trusted by native vmlinux')
        exports = {name:helper['parse_symbols'](sources[name][0]) for name in by_name.values()}
        providers = {}
        for name, symbols in exports.items():
            for symbol in symbols:
                if symbol in providers:
                    raise SystemExit(f'Duplicate system module export: {symbol}')
                providers[symbol] = name
        to_sign = {name for name, symbols in exports.items() if protected.intersection(symbols)}
        while True:
            add = set()
            for name in by_name.values():
                if name in to_sign:
                    continue
                for line in subprocess.check_output(['modprobe','--dump-modversions',str(sources[name][0])],text=True).splitlines():
                    _, symbol = line.split()
                    if symbol not in allowed and providers.get(symbol) in to_sign:
                        add.add(name)
            if not add:
                break
            to_sign.update(add)
        strip = Path.home()/'Documents/ctwo/kernel/ctwo-workspace/prebuilts/clang/host/linux-x86/clang-r487747c/bin/llvm-strip'
        depmod = Path.home()/'Documents/ctwo/kernel/ctwo-workspace/prebuilts/kernel-build-tools/linux-x86/bin/depmod'
        if not strip.is_file() or not depmod.is_file() or not (out/'scripts/sign-file').is_file():
            raise SystemExit('Missing native strip, depmod or sign-file tool')
        with tempfile.TemporaryDirectory(prefix='.ctwo-system-native-', dir=build) as d:
            root=Path(d);isolated=root/'system_dlkm';shutil.copytree(stage/'system_dlkm',isolated,symlinks=True)
            isolated_modules=isolated/'lib/modules'/RELEASE
            if not isolated_modules.resolve().is_relative_to(isolated.resolve()):
                raise SystemExit('Isolated module directory escapes the staging tree')
            load_hash = digest(isolated_modules/'modules.load')
            signed_count=0
            for row in results:
                name=row['name'];source=sources[name][0];matches=list(isolated_modules.rglob(name))
                if len(matches)!=1:
                    raise SystemExit(f'Isolated native stage has ambiguous module: {name}')
                target=matches[0]
                if target.is_symlink() or not target.resolve().is_relative_to(isolated.resolve()):
                    raise SystemExit(f'Unsafe isolated staging path: {name}')
                shutil.copyfile(source,target)
                subprocess.run([str(strip),'--strip-debug',str(target)],check=True)
                if name in to_sign:
                    subprocess.run([str(out/'scripts/sign-file'),'sha1',str(private),str(cert),str(target)],check=True)
                    if not helper['verify_signature'](target,cert,root):
                        raise SystemExit(f'Failed native signature verification: {name}')
                    signed_count+=1
                if helper['runtime_elf'](source)!=helper['runtime_elf'](target):
                    raise SystemExit(f'Native stage altered runtime ELF: {name}')
                row['isolated_native_sha256']=digest(target)
                row['isolated_signed']=name in to_sign
            completed=subprocess.run([str(depmod),'-b',str(isolated),'-e','-E',str(out/'Module.symvers'),RELEASE],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if completed.returncode or completed.stderr.strip():
                raise SystemExit('Native system_dlkm depmod validation failed: '+completed.stderr.strip())
            if digest(isolated_modules/'modules.load') != load_hash:
                raise SystemExit('Native metadata generation changed stock modules.load')
            if not all((isolated_modules/n).is_file() for n in ('modules.load','modules.dep','modules.alias','modules.softdep')):
                raise SystemExit('Native system_dlkm metadata generation incomplete')
            candidate_result={'status':'TEMPORARY NATIVE STAGE VALIDATED; NOT PUBLISHED',
                              'native_modules':60,'signed_modules':signed_count,
                              'signing_certificate_sha256':digest(cert),'depmod':'PASS',
                              'module_payload_bytes':sum(p.stat().st_size for p in isolated_modules.rglob('*.ko'))}
        errors = [x for x in errors if 'stock binary remains in system_dlkm stage' not in x]
    # Inspect only vendor modules that declare a direct dependency on this system set.
    cross = []
    vendor_records = [x for x in manifest['modules'] if 'vendor_dlkm' in x['partitions']]
    vendor_paths = list(vendorstage.glob('*.ko'))
    if len(vendor_records) != 281 or {x['name'] for x in vendor_records} != {x.name for x in vendor_paths}:
        errors.append('Vendor DLKM stage does not match the 281-module stock inventory')
    incompatible = []
    for path in vendor_paths:
        if not modinfo(path, 'vermagic').startswith(RELEASE+' '):
            incompatible.append(path.name)
    if incompatible:
        errors.append(f'{len(incompatible)} vendor_dlkm stage modules have incompatible vermagic')
    for path in vendorstage.glob('*.ko'):
        deps = [x for x in modinfo(path, 'depends').split(',') if key(x) in by_name]
        if not deps:
            continue
        vm = modinfo(path, 'vermagic')
        row = {'consumer': path.name, 'dependencies': deps, 'vermagic': vm, 'path': str(path)}
        cross.append(row)
        if not vm.startswith(RELEASE+' '):
            errors.append(f'{path.name}: staged cross-partition consumer has incompatible vermagic')
    report = {'status': 'BLOCKED', 'image_sha256': args.image_sha256,
              'stock_system_dlkm_sha256': STOCK_SHA256, 'partition_capacity': CAPACITY,
              'capacity_evidence': str(evidence), 'system_module_count': len(records),
              'native_source_count': sum(len(sources.get(x['name'], [])) == 1 for x in records),
              'stock_staged_count': stock_count, 'isolated_native_stage': candidate_result,
              'vendor_module_count':len(vendor_paths), 'vendor_incompatible_modules':sorted(incompatible),
              'verified_vendor_candidates':vendor_candidates,
              'modules': results, 'cross_partition_consumers': cross, 'blockers': errors}
    if not errors:
        report['blockers'].append('Image generation is not enabled: signature/protected-symbol closure, native dependency metadata and filesystem/AVB revalidation remain required')
    report_root = out/'system-dlkm-preflight'
    report_root.mkdir(parents=True, exist_ok=True)
    filename = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '.json'
    with tempfile.NamedTemporaryFile('w', dir=report_root, prefix='.tmp-', delete=False) as f:
        json.dump(report, f, indent=2, ensure_ascii=False);f.write('\n');temp = f.name
    os.replace(temp, report_root/filename)
    print(f'System DLKM preflight: {report_root/filename}')
    print(f'Native sources: {report["native_source_count"]}/60; stock binaries in stage: {report["stock_staged_count"]}/60')
    for error in report['blockers'][:12]:
        print('BLOCKED:', error)
    raise SystemExit('System DLKM image not published; see preflight report')

if __name__ == '__main__':
    main()

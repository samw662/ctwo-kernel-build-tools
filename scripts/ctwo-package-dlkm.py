#!/usr/bin/env python3
"""Create native CTWO DLKM development images without changing stock inputs."""
import argparse,collections,ctypes,hashlib,json,os,pathlib,runpy,shutil,struct,subprocess,sys,tempfile
from concurrent.futures import ThreadPoolExecutor
from elftools.elf.elffile import ELFFile
P=pathlib.Path
RELEASE='6.1.128—WearyStars⭐'
RC0='f50f7d6cd636428c2b68d4e1fec72577df47e7ba88ec0b19aa964975e5bb8753'
STOCK={'system_dlkm':('fa2577c5e78655a73cfbf74b3338bfb3cdee46d035f9ec34fba68ca4cdfabb99',11849728,'33fce6e544b12308dc428cd1fcc440039c7c4e185c4419a5db7d2d943c088c69','b9a769a7-2107-5447-b4df-5b05124dcdd0'),'vendor_dlkm':('1c0785206716049052cb2162919b8782f97a84a8ed5046a8d07970e222647a1c',25669632,'08d8206ad3d27bb4702a8ef38a6f9a6958824a08fda6616dd772c8e1d597b018','edb3cfe2-6e28-5e00-8513-aa6c51bcedf3')}
def fail(s):raise SystemExit(s)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for x in iter(lambda:f.read(1048576),b''):h.update(x)
 return h.hexdigest()
def call(args,**kw):return subprocess.run([str(x) for x in args],check=True,**kw)
def output(args):return subprocess.check_output([str(x) for x in args],text=True).strip()
def info(p,k):return output(['modinfo','-F',k,p])
def norm(s):return s.removesuffix('.ko').replace('-','_')
def main():
 ap=argparse.ArgumentParser()
 for x in ('out','build','stock','image-sha256'):ap.add_argument('--'+x,required=True)
 a=ap.parse_args();out,build,stock=map(P,(a.out,a.build,a.stock));image=out/'arch/arm64/boot/Image';rc=P.home()/'Documents/ctwo/kernel/build/weary-stars-rc0/rc0-manifest.json';IMAGE=a.image_sha256
 if len(IMAGE)!=64 or any(c not in '0123456789abcdef' for c in IMAGE) or sha(image)!=IMAGE or sha(rc)!=RC0:fail('Image or frozen inventory does not match selected baseline')
 for part,(h,cap,_,_) in STOCK.items():
  p=stock/'checking/modules/logical-images'/(part+'_a.img')
  if sha(p)!=h:fail('Stock image provenance mismatch: '+part)
 evidence=P.home()/'Documents/ctwo/logs/ctwo-fastbootd-20261108_093808.txt';s=evidence.read_text()
 if 'partition-size:vendor_dlkm_a: 0x187B000' not in s or 'partition-size:system_dlkm_a: 0xB4D000' not in s:fail('Missing verified partition capacity evidence')
 manifest=json.loads(rc.read_text());records={x['name']:x for x in manifest['modules']}
 if len(records)!=440 or len(manifest['modules'])!=440:fail('Unexpected frozen module inventory')
 wanted={part:{n for n,r in records.items() if part in r['partitions']} for part in STOCK}
 if len(wanted['system_dlkm'])!=60 or len(wanted['vendor_dlkm'])!=281 or wanted['system_dlkm']&wanted['vendor_dlkm']:fail('Unexpected DLKM inventories')
 pair=build/'boot-pairs'/IMAGE;pm=json.loads((pair/'manifest.json').read_text())
 for n in ('boot.img','vendor_boot.img'):
  if sha(pair/n)!=pm['images'][n]['sha256']:fail('Boot pair changed: '+n)
 if pm['kernel_sha256']!=IMAGE:fail('Boot pair baseline mismatch')
 for field in ('vmlinux','config','module_symvers'):
  if sha(P(pm[field]))!=pm[field+'_sha256']:fail('Boot-pair baseline artifact changed: '+field)
 helper=runpy.run_path(str(P(__file__).with_name('ctwo-package-boot.py')),run_name='helpers');current=helper['source_modules'](out);sources={};provenance={}
 for n in sorted(wanted['system_dlkm']|wanted['vendor_dlkm']):
  r=records[n];p=current.get(n)
  if p is None or not p.is_file():fail('Missing current native module: '+n)
  if info(p,'name').replace('-','_')!=norm(n) or not info(p,'vermagic').startswith(RELEASE+' '):fail('Module identity or vermagic mismatch: '+n)
  sources[n]=p;provenance[n]={'source':str(p),'source_sha256':sha(p),'origin':'current native OUT','partitions':sorted(r['partitions'])}
 kiwi=sources['qca_cld3_kiwi_v2.ko'];kiwi_cmd=out/'vendor/qcom/opensource/wlan/qcacld-3.0/core/hdd/src/.wlan_hdd_main.o.cmd'
 if '-DWLAN_CTRL_NAME=\\"wlan\\"' not in kiwi_cmd.read_text() or b'qcwlanstate' not in kiwi.read_bytes():fail('Kiwi WLAN control interface is not evidenced in the native build')
 # Check first-stage modules against the boot pair.
 bootnames={n for n,r in records.items() if 'vendor_boot' in r['partitions']};graph_sources={}
 for n in bootnames:
  r=pm['modules'][n];p=P(r['source'])
  if p!=current.get(n) or not p.is_file() or sha(p)!=r['sha256']:fail('Boot-pair source is not current native OUT: '+n)
  graph_sources[n]=p
 for n,p in sources.items():
  if n in graph_sources and sha(p)!=pm['modules'][n]['sha256'] and helper['runtime_elf'](p)!=helper['runtime_elf'](graph_sources[n]):fail('Shared module ELF differs from boot pair: '+n)
  graph_sources.setdefault(n,p)
 if set(graph_sources)!=set(records):fail('Native module graph does not cover all stock modules')
 # Read exports and imported versions from the ELF modules.
 exports={};versions={};namespaces={};owners={};needed=set()
 for n,p in sorted(graph_sources.items()):
  if not info(p,'vermagic').startswith(RELEASE+' '):fail('Graph vermagic mismatch: '+n)
  imp=output(['modprobe','--dump-modversions',p]).splitlines();versions[n]={sym:int(crc,16) for crc,sym in (x.split() for x in imp)}
  if not versions[n]:fail('No versioned imports: '+n)
  namespaces[n]=set(info(p,'import_ns').splitlines());needed.update(versions[n]);ex=helper['parse_symbols'](p)
  for sym,crc in ex.items():
   if sym in exports:fail('Duplicate native export: '+sym)
   exports[sym]=(crc,n)
  owners[n]=[norm(x) for x in info(p,'depends').split(',') if x]
 from elftools.elf.elffile import ELFFile
 kern={};linked={};sectioncache={}
 with (out/'vmlinux').open('rb') as f:
  e=ELFFile(f);tab=e.get_section_by_name('.symtab')
  if tab is None:fail('Missing vmlinux symbols')
  for x in tab.iter_symbols():
   n=x.name
   if n in ('__cert_list_start','__cert_list_end','gki_unprotected_symbols','gki_protected_exports_symbols'):linked[n]=x
   if not n.startswith('__crc_') or n[6:] not in needed:continue
   idx=x['st_shndx']
   if idx=='SHN_ABS':kern[n[6:]]=x['st_value']
   elif isinstance(idx,int):
    sec=e.get_section(idx);off=x['st_value']-sec['sh_addr']
    if sec['sh_type']!='SHT_NOBITS' and 0<=off<=sec.data_size-4:
     if idx not in sectioncache:sectioncache[idx]=sec.data()
     kern[n[6:]]=struct.unpack_from('<I',sectioncache[idx],off)[0]
  cert=out/'certs/signing_key.x509';start=linked.get('__cert_list_start');end=linked.get('__cert_list_end')
  if start is None or end is None or start['st_shndx']!=end['st_shndx']:fail('Cannot verify trusted kernel certificate')
  sec=e.get_section(start['st_shndx']);off=start['st_value']-sec['sh_addr']
  if cert.read_bytes() not in sec.data()[off:off+end['st_value']-start['st_value']]:fail('Signing certificate not linked in vmlinux')
  import re
  lists={}
  for label,file,macro in [('allowed','gki_module_unprotected.h','MAX_UNPROTECTED_NAME_LEN'),('protected','gki_module_protected_exports.h','MAX_PROTECTED_EXPORTS_NAME_LEN')]:
   text=(out/'include/generated'/file).read_text();values=set(re.findall(r'"([^\"]+)"',text));match=re.search(r'#define\s+'+macro+r'\s+\((\d+)\)',text);sn='gki_unprotected_symbols' if label=='allowed' else 'gki_protected_exports_symbols';sym=linked.get(sn)
   if not values or not match or sym is None:fail('Missing GKI allowlist')
   width=int(match.group(1));sec=e.get_section(sym['st_shndx']);off=sym['st_value']-sec['sh_addr'];raw=sec.data()[off:off+sym['st_size']];actual={raw[i:i+width].split(b'\0',1)[0].decode() for i in range(0,len(raw),width)}
   if len(raw)%width or actual!=values:fail('GKI generated/linked list mismatch: '+label)
   lists[label]=values
 # Check CRCs and namespaces against actual providers.
 symvers={};symvers_lines={};sv=[out/'Module.symvers']+list((out/'vendor').rglob('Module.symvers'))
 for source in graph_sources.values():
  parent=source.parent
  while parent!=parent.parent:
   candidate=parent/'Module.symvers'
   if candidate.is_file() and candidate not in sv:sv.append(candidate)
   if parent==out:break
   parent=parent.parent
 for p in sv:
  for line in p.read_text().splitlines():
   x=line.split('\t')
   if len(x)<4:fail('Malformed Module.symvers: '+str(p))
   value=(int(x[0],16),x[4] if len(x)>4 else '')
   if x[1] in symvers and symvers[x[1]]!=value:fail('Conflicting symbol CRC or namespace: '+x[1])
   symvers[x[1]]=value
   symvers_lines.setdefault(x[1],line)
 kernel_names={line.split('\t')[1] for line in (out/'Module.symvers').read_text().splitlines()
               if len(line.split('\t'))>=3 and line.split('\t')[2]=='vmlinux'}
 duplicates=kernel_names.intersection(exports)
 if duplicates:fail('Module exports duplicate kernel symbols: '+', '.join(sorted(duplicates)))
 name_map={norm(n):n for n in records};builtin={norm(P(x).name) for x in (out/'modules.builtin').read_text().splitlines() if x.endswith('.ko')}
 if len(name_map)!=440:fail('Normalized module name collision')
 for n,im in versions.items():
  for dep in owners[n]:
   if dep not in name_map and dep not in builtin:fail('Missing dependency: '+n+' -> '+dep)
  for sym,crc in im.items():
   if symvers.get(sym,(None,''))[0]!=crc:fail('Missing Module.symvers CRC: '+n+' '+sym)
   ns=symvers[sym][1]
   if ns and ns not in namespaces[n]:fail('Missing namespace: '+n+' '+sym+' '+ns)
   actual=exports.get(sym)
   if actual:
    if actual[0]!=crc:fail('Module provider CRC mismatch: '+n+' '+sym)
    if n in bootnames and actual[1] not in bootnames and sym not in lists['allowed']:fail('Unsigned boot consumer cannot import signed DLKM provider: '+n+' '+sym)
   elif kern.get(sym)!=crc:fail('No actual matching provider: '+n+' '+sym)
 print(f'[ok] symbol graph: {sum(map(len,versions.values()))} imports',flush=True)
 destroot=build/'dlkm-releases';dest=destroot/IMAGE;destroot.mkdir(parents=True,exist_ok=True)
 if dest.exists():fail('Refusing to overwrite release: '+str(dest))
 tools=P.home()/'Documents/ctwo/kernel/ctwo-workspace/prebuilts/kernel-build-tools/linux-x86/bin';strip=P.home()/'Documents/ctwo/kernel/ctwo-workspace/prebuilts/clang/host/linux-x86/clang-r487747c/bin/llvm-strip';sign=out/'scripts/sign-file';key=out/'certs/signing_key.pem';cert=out/'certs/signing_key.x509'
 public=subprocess.check_output(['openssl','pkey','-in',str(key),'-pubout','-outform','DER']);pem=subprocess.check_output(['openssl','x509','-inform','DER','-in',str(cert),'-pubkey','-noout']);cpub=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pem,stdout=subprocess.PIPE,check=True).stdout
 if public!=cpub:fail('Module key/certificate mismatch')
 with tempfile.TemporaryDirectory(prefix='.ctwo-dlkm-',dir=destroot) as td:
  tmp=P(td);candidate=tmp/'candidate';candidate.mkdir();overlay=tmp/'overlay';overlay.mkdir();scratch=tmp/'scratch';scratch.mkdir();system=overlay/'system_dlkm/lib/modules'/RELEASE;vendor=overlay/'vendor_dlkm/lib/modules';system.mkdir(parents=True);vendor.mkdir(parents=True)
  # Strip and sign copies, then check signatures and ELF content.
  def prepare(n):
   r=records[n];part='system_dlkm' if n in wanted['system_dlkm'] else 'vendor_dlkm';rel=P(r['partitions'][part]['rc0_path']).relative_to('partitions')
   destfile=overlay/rel;destfile.parent.mkdir(parents=True,exist_ok=True);src=sources[n]
   call([strip,'--strip-debug','-o',destfile,src]);call([sign,'sha1',key,cert,destfile])
   one=scratch/n;one.mkdir()
   if not helper['verify_signature'](destfile,cert,one):fail('Missing signed copy: '+n)
   if helper['runtime_elf'](src)!=helper['runtime_elf'](destfile):fail('Stripping or signing changed runtime ELF: '+n)
   return n,{'path':str(rel),'sha256':sha(destfile),'size':destfile.stat().st_size,'signature':'verified against built-in certificate'}
  built={}
  with ThreadPoolExecutor(max_workers=6) as pool:
   for n,result in pool.map(prepare,sorted(sources)):
    built[n]=result
  print(f'[ok] signed {len(built)} modules',flush=True)
  sysstock=stock/'checking/modules/system_dlkm/lib/modules';dirs=[p for p in sysstock.iterdir() if p.is_dir()];
  if len(dirs)!=1:fail('Unexpected stock system release directories')
  oldrelease=dirs[0].name;vendorstock=stock/'checking/modules/vendor_dlkm/lib/modules'
  shutil.copyfile(dirs[0]/'modules.load',system/'modules.load');shutil.copyfile(vendorstock/'modules.load',vendor/'modules.load')
  for n in ('modules.builtin','modules.builtin.modinfo'):shutil.copyfile(out/n,system/n)
  shutil.copyfile(out/'modules.order',system/'modules.order')
  depmod=tools/'depmod'
  def depmod_run(root):
   # Cross-partition providers were checked against their actual ELF exports above.
   # A partition-local depmod scan cannot enumerate those external modules.
   r=subprocess.run([str(depmod),'-b',str(root),RELEASE],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   if r.returncode or r.stderr.strip():fail('depmod failed: '+r.stderr.strip())
  depmod_run(overlay/'system_dlkm')
  scan=tmp/'vendor-scan';scanmods=scan/'lib/modules'/RELEASE;scanmods.mkdir(parents=True)
  for n in wanted['vendor_dlkm']:shutil.copyfile(vendor/n,scanmods/n)
  (scanmods/'modules.order').write_text(''.join(x+'\n' for x in (vendor/'modules.load').read_text().splitlines() if (scanmods/x).is_file()));(scanmods/'modules.builtin').write_text('');(scanmods/'modules.builtin.modinfo').write_text('');depmod_run(scan)
  lines=[]
  for line in (scanmods/'modules.dep').read_text().splitlines():
   l,sep,r=line.partition(':')
   if not sep:fail('Malformed vendor modules.dep')
   fields=[l.strip(),*r.split()];mapped=[]
   for x in fields:
    name=P(x).name
    if not (vendor/name).is_file():fail('Invalid vendor module path: '+x)
    mapped.append('/vendor/lib/modules/'+name)
   lines.append(mapped[0]+':'+(' '+' '.join(mapped[1:]) if len(mapped)>1 else ''))
  (vendor/'modules.dep').write_text('\n'.join(lines)+'\n');shutil.copyfile(scanmods/'modules.alias',vendor/'modules.alias')
  for part,original,target in [('system_dlkm',dirs[0],system),('vendor_dlkm',vendorstock,vendor)]:
   oldsoft=(original/'modules.softdep').read_text().splitlines();newsoft=(target/'modules.softdep').read_text().splitlines() if (target/'modules.softdep').exists() else (scanmods/'modules.softdep').read_text().splitlines();(target/'modules.softdep').write_text('\n'.join(oldsoft+[x for x in newsoft if x not in oldsoft])+'\n')
  for part,root in [('system_dlkm',system),('vendor_dlkm',vendor)]:
   listed=(root/'modules.load').read_text().splitlines()
   for n in listed:
    if n and not n.startswith('#') and not (root/n).is_file():fail('Missing stock load-list entry: '+part+' '+n)
   aliases=set((root/'modules.alias').read_text().splitlines())
   for path in root.rglob('*.ko'):
    module_name=info(path,'name')
    for alias in info(path,'alias').splitlines():
     if alias and f'alias {alias} {module_name}' not in aliases:fail('Native alias absent from generated metadata: '+part+' '+path.name+' '+alias)
  for n in ('cfg80211.ko','mac80211.ko','qca_cld3_kiwi_v2.ko'):
   if n not in (vendor/'modules.load').read_text().splitlines():fail('WLAN module absent from stock vendor load list: '+n)
  for n in ('rfkill.ko','libarc4.ko'):
   if not any(x.endswith('/'+n) for x in (system/'modules.load').read_text().splitlines()):fail('WLAN system provider absent from stock load list: '+n)
  system_requested={P(x).name for x in (system/'modules.load').read_text().splitlines() if x and not x.startswith('#')}
  vendor_requested={P(x).name for x in (vendor/'modules.load').read_text().splitlines() if x and not x.startswith('#')}
  blocklist=set()
  for line in (vendorstock/'system_dlkm.modules.blocklist').read_text().splitlines():
   fields=line.split()
   if len(fields)>=2 and fields[0]=='blocklist':blocklist.add(norm(fields[1]))
  boot_early=set(pm['first_stage_dependency_closure']);cross=[]
  for n in sorted(vendor_requested):
   if n not in owners:fail('Vendor load-list module missing from graph: '+n)
   for dep in owners[n]:
    if dep in builtin:continue
    provider=name_map[dep]
    if provider in wanted['system_dlkm']:
     if provider not in system_requested or dep in blocklist:fail('Vendor consumer requires an unrequested or blocked system provider: '+n+' -> '+provider)
     cross.append({'consumer':n,'provider':provider,'phase':'system before vendor; job success unverified'})
    elif provider not in wanted['vendor_dlkm']:
     if provider not in boot_early:fail('Vendor consumer requires a boot provider outside first-stage closure: '+n+' -> '+provider)
     cross.append({'consumer':n,'provider':provider,'phase':'vendor_boot first stage; runtime success unverified'})
  # Keep candidate metadata with the images.
  (candidate/'metadata').mkdir();(candidate/'reports').mkdir();(candidate/'images').mkdir()
  env=os.environ.copy();env['PATH']=str(tools)+os.pathsep+env.get('PATH','')
  archive_script=P(__file__).with_name('ctwo-erofs-archive.py')
  for part,(stockhash,capacity,salt,uuid) in STOCK.items():
   mount=tmp/('mount-'+part);mount.mkdir();archive=tmp/(part+'.tar');expected=candidate/'metadata'/(part+'-filesystem.json');stockimg=stock/'checking/modules/logical-images'/(part+'_a.img');oldver=oldrelease if part=='system_dlkm' else '';newver=RELEASE if oldver else ''
   shell='set -eu; erofsfuse "$1" "$2" >/dev/null; trap \'fusermount3 -u "$2"\' EXIT; python3 "$3" archive "$2" "$4" "$5" "$6" "$7" "$8"'
   call(['unshare','-Ur','-m','bash','-c',shell,'_',stockimg,mount,archive_script,overlay/part,archive,expected,oldver,newver])
   img=candidate/'images'/(part+'.img');call(['/usr/bin/mkfs.erofs','-b4096','-U',uuid,'-T0','--mkfs-time','--preserve-mtime','-zlz4hc,level=12','-C65536','--tar=f',img,archive],stdout=subprocess.DEVNULL)
   if img.stat().st_size>=capacity:fail('EROFS image exceeds partition capacity before AVB: '+part)
   call(['/usr/bin/fsck.erofs',img],stdout=subprocess.DEVNULL)
   # FEC and footer use the stock descriptor parameters; algorithm NONE is not trust.
   cmd=['avbtool','add_hashtree_footer','--image',img,'--partition_size',capacity,'--partition_name',part,'--hash_algorithm','sha256','--block_size','4096','--fec_num_roots','2','--salt',salt,'--algorithm','NONE','--rollback_index','0','--flags','0']
   if part=='vendor_dlkm':cmd+=['--prop','com.android.build.vendor_dlkm.os_version:14','--prop','com.android.build.vendor_dlkm.fingerprint:motorola/ctwo/ctwo:14/UUV3S4HV-W1-ST14/cb805:user/release-keys']
   call(cmd,env=env)
   if img.stat().st_size!=capacity:fail('Final image size does not match partition capacity: '+part)
   call(['avbtool','verify_image','--image',img],env=env)
   avbinfo=output(['avbtool','info_image','--image',img]);import re
   match=re.search(r'FEC offset:\s*(\d+).*?FEC size:\s*(\d+)',avbinfo,re.S)
   if not match or not re.search(r'^Algorithm:\s+NONE\s*$',avbinfo,re.M):fail('Invalid AVB FEC/algorithm metadata: '+part)
   fecoff,fecsize=map(int,match.groups());raw=img.read_bytes();fectarget=tmp/(part+'-fec-input');fectarget.write_bytes(raw[:fecoff]);fecout=tmp/(part+'-fec-output')
   call([tools/'fec','--encode','--roots','2',fectarget,fecout],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   generated=fecout.read_bytes();header=struct.unpack('<LLLLLQ32s',generated[-60:])
   if header[0]!=0xfecfecfe or header[3]!=2 or header[4]!=fecsize or generated[:fecsize]!=raw[fecoff:fecoff+fecsize]:fail('FEC parity mismatch: '+part)
   shell='set -eu; erofsfuse "$1" "$2" >/dev/null; trap \'fusermount3 -u "$2"\' EXIT; python3 "$3" verify "$2" "$4" "$5" "$6" "$7" "$8"'
   call(['unshare','-Ur','-m','bash','-c',shell,'_',img,mount,archive_script,overlay/part,archive,expected,oldver,newver])
  result={'status':'NO-GO: development AVB structures self-verify only; bootloader trust and runtime loading unverified','kernel_image':str(image),'kernel_sha256':IMAGE,'module_symvers_sha256':sha(out/'Module.symvers'),'certificate_sha256':sha(cert),'native_modules':{n:{**provenance[n],**built[n]} for n in sorted(built)},'images':{part:{'sha256':sha(candidate/'images'/(part+'.img')),'size':(candidate/'images'/(part+'.img')).stat().st_size,'capacity':STOCK[part][1]} for part in STOCK},'cross_partition_dependencies':cross,'wlan_control':'Kiwi recorded build command defines WLAN_CTRL_NAME=wlan; module contains control-device registration strings','loader':'Stock load lists and blocklists preserved; system loader waits for parallel jobs without checking all results; cross-partition runtime availability remains unverified','avb':'NONE footers self-verify; signed stock root vbmeta does not authenticate changed payloads'}
  (candidate/'manifest.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
  libc=ctypes.CDLL(None,use_errno=True)
  if not hasattr(libc,'renameat2') or libc.renameat2(-100,os.fsencode(candidate),-100,os.fsencode(dest),1)!=0:fail('Atomic no-overwrite publication failed')
 print('[ok] system_dlkm.img',flush=True)
 print('[ok] vendor_dlkm.img',flush=True)
 print('Development DLKM images: stock vbmeta does not authenticate these payloads.',flush=True)
if __name__=='__main__':main()

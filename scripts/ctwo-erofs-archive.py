#!/usr/bin/env python3
"""Create and verify an EROFS source archive using mounted stock metadata."""
import hashlib,json,os,pathlib,stat,sys,tarfile
mode,root,overlay,archive,expected,oldrelease,newrelease=sys.argv[1:]
root=pathlib.Path(root);overlay=pathlib.Path(overlay);archive=pathlib.Path(archive);expected=pathlib.Path(expected)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def details(p):
 st=p.lstat();r={'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'type':stat.S_IFMT(st.st_mode),'xattrs':{k:os.getxattr(p,k,follow_symlinks=False).decode('utf-8') for k in os.listxattr(p,follow_symlinks=False)}}
 if p.is_symlink():r['link']=os.readlink(p)
 elif p.is_file():r['sha256']=sha(p)
 return r
def remap(name):
 old='lib/modules/'+oldrelease
 return ('lib/modules/'+newrelease+name[len(old):]) if oldrelease and (name==old or name.startswith(old+'/')) else name
if mode=='archive':
 found={}; paths=[root]+sorted(root.rglob('*'))
 with tarfile.open(archive,'w',format=tarfile.PAX_FORMAT,dereference=False) as tar:
  for p in paths:
   old='.' if p==root else p.relative_to(root).as_posix();name=remap(old);info=details(p);src=p
   if oldrelease and p.is_symlink() and oldrelease in info.get('link',''):raise SystemExit('Release-specific stock symlink requires review: '+old)
   if p.is_file() and not p.is_symlink():
    target=overlay/name
    if target.is_file():src=target;info['sha256']=sha(src)
    elif name.endswith('.ko'):raise SystemExit('Missing native staged module: '+name)
   item=tar.gettarinfo(str(p),arcname=name);item.pax_headers.update({'SCHILY.xattr.'+k:v for k,v in info['xattrs'].items()})
   if item.isfile():
    item.size=src.stat().st_size
    with src.open('rb') as f:tar.addfile(item,f)
   else:tar.addfile(item)
   if name in found:raise SystemExit('Duplicate destination path: '+name)
   found[name]=info
 expected.write_text(json.dumps(found,indent=2,sort_keys=True)+'\n')
 print(f'[ok] EROFS archive: {len(found)} entries')
elif mode=='verify':
 want=json.loads(expected.read_text());got={('.' if p==root else p.relative_to(root).as_posix()):details(p) for p in [root]+sorted(root.rglob('*'))}
 if got!=want:
  for k in sorted(set(got)|set(want)):
   if got.get(k)!=want.get(k):print('MISMATCH',k,got.get(k),want.get(k),file=sys.stderr)
  raise SystemExit('EROFS content or metadata mismatch')
 print(f'[ok] EROFS metadata: {len(got)} entries')
else:raise SystemExit('Unknown mode')

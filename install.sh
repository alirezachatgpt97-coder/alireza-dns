#!/usr/bin/env bash
# Alirezadns standalone 1.0.0 — online source-built HyperDNS distribution.
# Source and license notices are included and served at /alirezadns-source.
set -Eeuo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MANAGER=/opt/alirezadns-manager
case "${1:-}" in
 --help|-h) printf '%s\n' 'sudo bash install.sh [--repair|--info|--check|--update]' 'Fresh install needs a public IPv4 and domain pointing directly to it.'; exit 0;;
 ''|--repair|--info|--check|--update) ;;
 *) echo 'Unknown option. Use --help.' >&2; exit 1;;
esac
[[ $EUID == 0 ]] || { echo 'Run with sudo bash install.sh' >&2; exit 1; }
case "${1:-}" in
 --info|--check|--update)
  [[ -f "$MANAGER/agent.py" ]] || { echo 'Install Alirezadns first.' >&2; exit 1; }
  if [[ $1 == --update ]]; then exec python3 "$MANAGER/agent.py" --update --retry; fi
  exec python3 "$MANAGER/agent.py" "$1";;
esac
[[ -d /run/systemd/system ]] || { echo 'A Linux server with systemd is required.' >&2; exit 1; }
source /etc/os-release
case "$ID:$VERSION_ID" in ubuntu:24.04|debian:12|debian:13) ;; *) echo 'Supported: Ubuntu 24.04, Debian 12/13.' >&2; exit 1;; esac
case "$(uname -m)" in x86_64|aarch64) ;; *) echo 'amd64/arm64 required.' >&2; exit 1;; esac
command -v flock >/dev/null || { echo 'Install util-linux first.' >&2; exit 1; }
exec 9>/run/alirezadns-installer.lock
flock -n 9 || { echo 'Another installer is running.' >&2; exit 1; }
echo 'Alirezadns: preparing verified source build. Initial compilation can take several minutes.'
apt-get -o DPkg::Lock::Timeout=300 update
apt-get -o DPkg::Lock::Timeout=300 install -y python3 ca-certificates iptables
STAGE=$(mktemp -d)
trap 'rm -rf -- "$STAGE"' EXIT

cat > "$STAGE/agent.py" <<'ALIREZADNS_A4D4ABE4295DB708A8A40C6A'
#!/usr/bin/python3
"""Alirezadns standalone installer/updater. Built from corresponding branded source."""
import base64, contextlib, fcntl, hashlib, http.client, ipaddress, json, os, pathlib, platform, re, secrets, shutil, socket, struct, subprocess, sys, tempfile, time, urllib.request
APP=pathlib.Path('/opt/hyperdns')
AGENT=pathlib.Path('/opt/alirezadns-manager')
BACKUPS=pathlib.Path('/var/backups/alirezadns')
META=AGENT/'node.json'
PENDING=AGENT/'pending.json'
VERSION='v2.2.0-beta.1'
PIN={'amd64':'17d9015200115878a375f74c56cff2c6b9e22e682a7ceab61104f55d54c7f6bf','arm64':'ca19bfb5b144838ef3d28b5d29074534084ee54713594d297a076e23cc551e98'}
PORTS=[53,80,443,8080,853,8443,5222,5223,2099,8393]
def run(args,timeout=180):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout).stdout
def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp=path.with_suffix('.new')
    with open(temp,'w') as stream:
        os.chmod(temp,0o600);json.dump(data,stream);stream.flush();os.fsync(stream.fileno())
    os.replace(temp,path)
    if os.name=='posix':
        fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
def read(path):return json.loads(path.read_text())
class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,url):
        if not url.startswith('https://'):raise RuntimeError('Unencrypted release redirect refused')
        return super().redirect_request(req,fp,code,msg,headers,url)
def fetch(url,limit=96*1024*1024):
    if not url.startswith('https://'):raise RuntimeError('HTTPS required')
    with urllib.request.build_opener(HTTPSOnly).open(urllib.request.Request(url,headers={'User-Agent':'alirezadns/0.5'}),timeout=45) as r:
        data=r.read(limit+1)
        if len(data)>limit:raise RuntimeError('Download too large')
        return data
def binary(version,arch,expected=None):
    from builder import build
    return build(version,arch,AGENT)

def dns_probe(host):
    ident=secrets.token_bytes(2);question=ident+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07invalid\x00\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(8);s.sendto(question,(host,53));reply=s.recv(4096)
        if reply[:2]!=ident or len(reply)<12 or not(reply[2]&128):raise RuntimeError('UDP DNS check failed')
    with socket.create_connection((host,53),8) as s:
        s.sendall(struct.pack('!H',len(question))+question);f=s.makefile('rb');size=f.read(2)
        if len(size)!=2:raise RuntimeError('TCP DNS header missing')
        reply=f.read(struct.unpack('!H',size)[0])
        if reply[:2]!=ident or len(reply)<12 or not(reply[2]&128):raise RuntimeError('TCP DNS check failed')
def health(meta):
    run(['systemctl','is-active','--quiet','hyperdns.service'])
    # Read the daemon's root-only control socket; path/port rotation must not
    # turn an otherwise healthy update into a false failure.
    conn=http.client.HTTPConnection('localhost',timeout=10)
    conn.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);conn.sock.settimeout(10);conn.sock.connect('/run/hyperdns/control.sock')
    try:
        conn.request('GET','/v1/settings',headers={'X-HyperDNS-Control-Version':'v1'});response=conn.getresponse()
        if response.status!=200:raise RuntimeError('Control settings unavailable')
        settings=json.loads(response.read(131072))
    finally:conn.close()
    meta['adminPath']=settings['admin_path'];meta['port']=settings['web_port']
    base='https://'+meta['domain']+':'+str(meta['port'])+'/'+meta['adminPath']
    for path,marker in [('/dash/login',b'/api/auth/login'),('/js/app.js',b'const ADMIN_BASE = (function () {')]:
        if marker not in fetch(base+path,8*1024*1024):raise RuntimeError('Remote panel contract check failed')
    dns_probe(meta['bindIP'])
def wait_health(meta,attempts=20):
    for _ in range(attempts):
        try:health(meta);return
        except Exception:time.sleep(3)
    raise RuntimeError('Panel HTTPS or DNS health check failed; inspect journalctl -u hyperdns')
def recover():
    if not PENDING.exists():return
    journal=read(PENDING);backup=pathlib.Path(journal['backup']).resolve()
    if backup.parent!=BACKUPS.resolve() or not (backup/'hyperdns').is_file():raise RuntimeError('Invalid recovery snapshot')
    stage=APP.with_name('alirezadns-restored')
    if stage.exists():shutil.rmtree(stage)
    shutil.copytree(backup,stage,symlinks=True)
    if APP.exists():shutil.rmtree(APP)
    os.replace(stage,APP);save(META,journal['previous']);PENDING.unlink()
def update():
    if PENDING.exists():
        run(['systemctl','stop','hyperdns.service']);recover();run(['systemctl','start','hyperdns.service']);wait_health(read(META))
    meta=read(META)
    release=json.loads(fetch('https://api.github.com/repos/IzumiRain/HyperDNS/releases/latest',2*1024*1024));version=release['tag_name']
    if version==meta['version']:return
    if not re.fullmatch(r'v2\.\d+\.\d+(?:-[A-Za-z0-9.]+)?',version):raise RuntimeError('New major version requires integration review')
    if tuple(map(int,re.findall(r'\d+',version)[:3]))<tuple(map(int,re.findall(r'\d+',meta['version'])[:3])):raise RuntimeError('Downgrade refused')
    status=AGENT/'update-status.json'
    if status.exists() and read(status).get('rejected')==version:return
    data=binary(version,meta['arch']);health(meta)
    if APP.is_symlink():raise RuntimeError('Custom installation path refused')
    size=sum(p.stat().st_size for p in APP.rglob('*') if p.is_file())
    if shutil.disk_usage(APP).free<size*3+len(data)+64*1024*1024:raise RuntimeError('Not enough space for backup')
    BACKUPS.mkdir(parents=True,exist_ok=True,mode=0o700)
    backup=BACKUPS/str(time.time_ns());stopped=False
    try:
        run(['systemctl','stop','hyperdns.service']);stopped=True
        shutil.copytree(APP,backup,symlinks=True)
        save(PENDING,{'backup':str(backup),'previous':meta})
        target=APP/'hyperdns.new';target.write_bytes(data);os.chmod(target,0o755);os.replace(target,APP/'hyperdns');shutil.copy2(AGENT/'candidate-source.tar.gz',APP/'alirezadns-source.tar.gz')
        run(['systemctl','start','hyperdns.service']);stopped=False
        wait_health(meta);meta['version']=version;save(META,meta);PENDING.unlink()
        save(status,{'ok':True,'version':version,'at':int(time.time())})
        for old in sorted(BACKUPS.iterdir())[:-2]:
            if old.is_dir():shutil.rmtree(old)
    except Exception:
        if PENDING.exists():
            run(['systemctl','stop','hyperdns.service']);recover();run(['systemctl','start','hyperdns.service']);wait_health(read(META))
        elif stopped:run(['systemctl','start','hyperdns.service'])
        save(status,{'ok':False,'rejected':version,'at':int(time.time())});raise
def install(cfg):
    AGENT.mkdir(parents=True,exist_ok=True,mode=0o700)
    for name,target in [('agent.py','agent.py'),('builder.py','builder.py')]:
        source=pathlib.Path(__file__).with_name(name)
        if source.resolve()!=(AGENT/target).resolve():shutil.copy2(source,AGENT/target)

    if pathlib.Path('/opt/nova-node-agent').exists() or pathlib.Path('/var/lib/alirezaserver').exists():raise RuntimeError('Refusing to install on the main panel server')
    if META.exists():
        meta=read(META)
        if cfg['domain']!=meta['domain']:raise RuntimeError('Existing managed node has a different domain')
        run(['systemctl','restart','hyperdns.service']);wait_health(meta,120);save(META,meta)
        run(['systemctl','enable','--now','alirezadns-update.timer']);return meta
    if APP.exists() or pathlib.Path('/etc/systemd/system/hyperdns.service').exists():raise RuntimeError('Existing independent HyperDNS installation was not overwritten')
    if not pathlib.Path('/run/systemd/system').is_dir():raise RuntimeError('systemd required')
    osinfo=pathlib.Path('/etc/os-release').read_text()
    if not re.search(r'^ID=(?:"?)(?:ubuntu|debian)(?:"?)$',osinfo,re.M):raise RuntimeError('Remote installation supports Ubuntu/Debian')
    ip=str(ipaddress.IPv4Address(cfg['host']));domain=cfg['domain']
    if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',domain) or '.' not in domain:raise RuntimeError('Invalid domain')
    if ip not in socket.gethostbyname_ex(domain)[2]:raise RuntimeError('Domain A record must point directly to the destination IP')
    bind=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);bind.connect(('1.1.1.1',53));bindIP=bind.getsockname()[0];bind.close()
    for port in PORTS:
        for kind in ([socket.SOCK_STREAM,socket.SOCK_DGRAM] if port==53 else [socket.SOCK_STREAM]):
            with socket.socket(socket.AF_INET,kind) as s:
                try:s.bind((bindIP,port))
                except OSError:raise RuntimeError('Destination port '+str(port)+' is occupied; no service was stopped')
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    if not arch:raise RuntimeError('amd64/arm64 required')
    data=binary(VERSION,arch,PIN[arch])
    run(['apt-get','-o','DPkg::Lock::Timeout=300','update'],600)
    run(['apt-get','-o','DPkg::Lock::Timeout=300','install','-y','ca-certificates','iptables'],600)
    APP.mkdir(mode=0o700);(APP/'certs').mkdir(mode=0o700)
    (APP/'hyperdns').write_bytes(data);os.chmod(APP/'hyperdns',0o755);shutil.copy2(AGENT/'candidate-source.tar.gz',APP/'alirezadns-source.tar.gz')
    password=secrets.token_urlsafe(24)
    save(APP/'config.json',{'server':{'public_ip':ip,'bind_host':bindIP,'web_port':8080,'admin_username':'admin','admin_password':password,'api_key':'hdns_live_'+secrets.token_hex(24)},'dns':{'enabled':True,'port':53,'dot_port':853,'doh_port':8443},'tls':{'domain':domain,'email':cfg.get('email',''),'auto_cert':True,'cert_file':str(APP/'certs/cert.pem'),'key_file':str(APP/'certs/key.pem')},'access':{'allow_all':False}})
    AGENT.mkdir(parents=True,exist_ok=True,mode=0o700)

    unit='''[Unit]
Description=Alirezadns standalone DNS engine
After=network-online.target alirezadns-firewall.service
Wants=network-online.target
Requires=alirezadns-firewall.service
[Service]
Type=simple
WorkingDirectory=/opt/hyperdns
RuntimeDirectory=hyperdns
RuntimeDirectoryMode=0700
ExecStartPre=/usr/bin/python3 /opt/alirezadns-manager/agent.py --recover
ExecStart=/opt/hyperdns/hyperdns -daemon -db /opt/hyperdns/data.db -key /opt/hyperdns/master.key -config /opt/hyperdns/config.json
Restart=on-failure
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
'''
    pathlib.Path('/etc/systemd/system/hyperdns.service').write_text(unit)
    firewall='''#!/bin/sh
set -eu
iptables -N ALIREZADNS 2>/dev/null || true
iptables -F ALIREZADNS
iptables -A ALIREZADNS -p tcp -m multiport --dports 53,80,443,8080,853,8443,5222,5223,2099,8393 -j ACCEPT
iptables -A ALIREZADNS -p udp --dport 53 -j ACCEPT
iptables -C INPUT -j ALIREZADNS 2>/dev/null || iptables -I INPUT 1 -j ALIREZADNS
'''
    (AGENT/'firewall.sh').write_text(firewall);os.chmod(AGENT/'firewall.sh',0o700)
    pathlib.Path('/etc/systemd/system/alirezadns-firewall.service').write_text('[Unit]\nDescription=Alirezadns standalone ports\nAfter=network-online.target ufw.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /opt/alirezadns-manager/firewall.sh\n')
    pathlib.Path('/etc/systemd/system/alirezadns-update.service').write_text('[Unit]\nDescription=alirezadns verified update\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /opt/alirezadns-manager/agent.py --update\nExecStopPost=/usr/bin/python3 /opt/alirezadns-manager/agent.py --recover-start\nTimeoutStartSec=90min\nUMask=0077\n')
    pathlib.Path('/etc/systemd/system/alirezadns-update.timer').write_text('[Unit]\nDescription=Check alirezadns engine releases\n[Timer]\nOnCalendar=*-*-* 01,07,13,19:00:00\nRandomizedDelaySec=20min\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
    meta={'host':ip,'bindIP':bindIP,'domain':domain,'adminPath':'','arch':arch,'version':VERSION,'username':'admin','password':password,'port':8080}
    save(META,meta)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','hyperdns.service'])
    wait_health(meta,120);save(META,meta)
    run(['systemctl','enable','--now','alirezadns-update.timer']);return meta
def main():
    if os.geteuid()!=0:raise RuntimeError('Root required')
    with open('/run/alirezadns.lock','w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            if '--recover' in sys.argv:return
            raise RuntimeError('Another remote operation is running')
        if '--recover-start' in sys.argv:
            if PENDING.exists():run(['systemctl','stop','hyperdns.service']);recover();run(['systemctl','start','hyperdns.service']);wait_health(read(META))
        elif '--recover' in sys.argv:recover()
        elif '--info' in sys.argv:
            meta=read(META)
            print('Alirezadns: https://'+meta['domain']+':'+str(meta['port'])+'/'+meta['adminPath']+'/dash/')
            print('Initial username: '+meta['username']+'\nInitial password: '+meta['password'])
        elif '--check' in sys.argv:health(read(META));print('Alirezadns HTTPS / UDP DNS / TCP DNS: OK')
        elif '--update' in sys.argv:
            if '--retry' in sys.argv:(AGENT/'update-status.json').unlink(missing_ok=True)
            update()
        elif '--install' in sys.argv:print(json.dumps({'ok':True,'node':install(json.load(sys.stdin))}))
        else:raise RuntimeError('Unknown operation')
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps({'ok':False,'error':str(e)[:400]}));sys.exit(1)
ALIREZADNS_A4D4ABE4295DB708A8A40C6A

cat > "$STAGE/builder.py" <<'ALIREZADNS_3EB154DCE7BCC64001BD5567'
#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build HyperDNS with display branding; preserve protocols and native handlers."""
import base64,hashlib,io,json,os,pathlib,re,shutil,subprocess,tarfile,tempfile,urllib.request,zipfile
COMMIT='4a899a90c682d14aa8fdc4506dd6efd84316956c'
SOURCE_SHA='6cab5bbecd98284ea57ad83194162c7240dc49c8145bae75bb65628c9462813b'
INITIAL='v2.2.0-beta.1'
REPO='https://github.com/alirezachatgpt97-coder/alireza-dns'
class HTTPSOnly(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,url):
  if not url.startswith('https://'):raise RuntimeError('Unencrypted redirect refused')
  return super().redirect_request(req,fp,code,msg,headers,url)
def fetch(url,limit=160*1024*1024):
 if not url.startswith('https://'):raise RuntimeError('HTTPS required')
 with urllib.request.build_opener(HTTPSOnly).open(urllib.request.Request(url,headers={'User-Agent':'Alirezadns-standalone/1.0'}),timeout=90) as r:
  data=r.read(limit+1)
  if len(data)>limit:raise RuntimeError('Download limit exceeded')
  return data
def extract(data,dest):
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
  members=t.getmembers()
  if len(members)>30000 or sum(m.size for m in members)>200*1024*1024:raise RuntimeError('Source archive too large')
  for m in members:
   p=pathlib.PurePosixPath(m.name)
   if p.is_absolute() or '..' in p.parts or not(m.isfile() or m.isdir()):raise RuntimeError('Unsafe source archive')
   target=dest.joinpath(*p.parts)
   if m.isdir():target.mkdir(parents=True,exist_ok=True)
   else:
    target.parent.mkdir(parents=True,exist_ok=True)
    with t.extractfile(m) as src,open(target,'wb') as out:shutil.copyfileobj(src,out)
    os.chmod(target,m.mode&0o755)
 roots=list(dest.iterdir())
 if len(roots)!=1 or not (roots[0]/'go.mod').exists():raise RuntimeError('Unexpected source layout')
 return roots[0]
def patch_source(root):
 if (root/'ALIREZADNS-CHANGES.md').exists():raise RuntimeError('Source already branded')
 targets=['web/index.html','web/login.html','web/js/app.js','web/js/i18n.js','web/js/portal.js','internal/web/portal.go','internal/web/portal_i18n.go','internal/database/subscription_access.go']
 for name in targets:
  p=root/name
  if not p.exists():raise RuntimeError('Upstream UI layout changed: '+name)
  text=p.read_text(encoding='utf-8');text=re.sub(r'HyperDNS|HyperRAIN|HyperSHIELD','Alirezadns',text)
  if name.endswith('.html') or name=='internal/web/portal.go':
   text=text.replace('</body>','<footer style="text-align:center;padding:8px;font-size:12px"><a href="/alirezadns-source">Alirezadns source · AGPL-3.0 · Based on HyperDNS</a></footer>\n</body>')
  p.write_text(text,encoding='utf-8',newline='\n')
 # A narrow public source-download route, never a directory server.
 p=root/'internal/web/server.go';s=p.read_text(encoding='utf-8');needle='\t\tp := cleanRequestPath(r.URL.Path)'
 if needle not in s:raise RuntimeError('Upstream routing changed; integration review required')
 if s.count(needle)!=3:raise RuntimeError('Upstream public surfaces changed; integration review required')
 s=s.replace(needle,needle+'\n\t\tif p == "/alirezadns-source" { serveAlirezadnsSource(w, r); return }');p.write_text(s,encoding='utf-8',newline='\n')
 (root/'internal/web/alirezadns_source.go').write_text('''// SPDX-License-Identifier: AGPL-3.0-or-later
package web
import "net/http"
func serveAlirezadnsSource(w http.ResponseWriter, r *http.Request) {
 if r.Method != http.MethodGet && r.Method != http.MethodHead { w.Header().Set("Allow", "GET, HEAD"); http.Error(w,"method not allowed",http.StatusMethodNotAllowed); return }
 w.Header().Set("Content-Type", "application/gzip")
 w.Header().Set("Content-Disposition", "attachment; filename=Alirezadns-source.tar.gz")
 http.ServeFile(w,r,"/opt/hyperdns/alirezadns-source.tar.gz")
}
''',encoding='utf-8')
 # Update only branding expectations; retain the original behavioral assertions.
 for name in ['document_structure_test.go','login_page_test.go','subscription_test.go']:
  p=root/'internal/web'/name;p.write_text(p.read_text(encoding='utf-8').replace('HyperDNS','Alirezadns'),encoding='utf-8',newline='\n')
 p=root/'internal/web/method_allow_test.go';s=p.read_text(encoding='utf-8');needle='var allowSourceFiles = []string{'
 if needle not in s:raise RuntimeError('Upstream method checks changed')
 p.write_text(s.replace(needle,needle+'"alirezadns_source.go", ',1),encoding='utf-8',newline='\n')
 (root/'internal/web/alirezadns_source_test.go').write_text('''package web
import ("net/http"; "net/http/httptest"; "testing")
func TestAlirezadnsSourceRejectsWrites(t *testing.T) {
 for _,method := range []string{"POST","PUT","DELETE","PATCH"} {
  w:=httptest.NewRecorder(); serveAlirezadnsSource(w,httptest.NewRequest(method,"/alirezadns-source",nil))
  if w.Code!=http.StatusMethodNotAllowed || w.Header().Get("Allow")!="GET, HEAD" {t.Fatalf("unexpected response for %s: %d",method,w.Code)}
 }
}
''',encoding='utf-8')
 p=root/'version.json';v=json.loads(p.read_text());v['homepage']=REPO;v['codename']='Alirezadns';p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
 (root/'ALIREZADNS-CHANGES.md').write_text('''# Alirezadns standalone modifications

Display branding in dashboard, login, subscriber portal and default portal title.
Original HyperDNS copyright notices and AGPL-3.0 license remain in LICENSE.
Native DNS, proxy, access control, API and account behavior are retained.
A GET/HEAD /alirezadns-source route distributes this corresponding source archive.
Build: CGO_ENABLED=0 go build -trimpath -o hyperdns ./cmd/hyperdns
The included builder.py documents fetching, checksums and branding changes.
Do not run patch_source again on these already branded sources.
Project: '''+REPO+'\nOriginal: https://github.com/IzumiRain/HyperDNS\n',encoding='utf-8')
def toolchain(agent,arch):
 version='v0.0.1-go1.26.4.linux-'+arch;module='golang.org/toolchain';target=agent/('go1.26.4-'+arch)
 if (target/'bin/go').is_file():return target/'bin/go'
 data=fetch('https://proxy.golang.org/'+module+'/@v/'+version+'.zip')
 lookup=fetch('https://sum.golang.org/lookup/'+module+'@'+version,65536).decode()
 matches=[line.split()[2] for line in lookup.splitlines() if line.startswith(module+' '+version+' ')]
 if len(matches)!=1:raise RuntimeError('Toolchain checksum unavailable')
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  names=sorted(n for n in z.namelist() if not n.endswith('/'))
  if sum(i.file_size for i in z.infolist())>500*1024*1024:raise RuntimeError('Toolchain too large')
  digest=hashlib.sha256()
  for n in names:digest.update((hashlib.sha256(z.read(n)).hexdigest()+'  '+n+'\n').encode())
  if 'h1:'+base64.b64encode(digest.digest()).decode()!=matches[0]:raise RuntimeError('Official Go module checksum mismatch')
  stage=pathlib.Path(tempfile.mkdtemp(prefix='go-stage-',dir=agent))
  try:
   prefix=module+'@'+version+'/'
   for n in names:
    if not n.startswith(prefix):raise RuntimeError('Invalid toolchain path')
    relative=pathlib.PurePosixPath(n[len(prefix):])
    if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('Unsafe toolchain path')
    p=stage.joinpath(*relative.parts);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(n));os.chmod(p,0o755 if n.startswith(prefix+'bin/') or n.startswith(prefix+'pkg/tool/') else 0o644)
   os.replace(stage,target)
  finally:
   if stage.exists():shutil.rmtree(stage)
 return target/'bin/go'
def build(version,arch,agent):
 agent=pathlib.Path(agent);agent.mkdir(parents=True,exist_ok=True,mode=0o700)
 if not re.fullmatch(r'v2\.\d+\.\d+(?:-[A-Za-z0-9.]+)?',version):raise RuntimeError('Unsupported upstream release')
 ref=COMMIT if version==INITIAL else version
 data=fetch('https://codeload.github.com/IzumiRain/HyperDNS/tar.gz/'+ref,32*1024*1024)
 digest=hashlib.sha256(data).hexdigest()
 if version==INITIAL and digest!=SOURCE_SHA:raise RuntimeError('Pinned source checksum mismatch')
 with tempfile.TemporaryDirectory(prefix='build-',dir=agent) as tmp:
  root=extract(data,pathlib.Path(tmp));patch_source(root);shutil.copy2(__file__,root/'builder.py')
  (root/'ALIREZADNS-UPSTREAM.json').write_text(json.dumps({'ref':ref,'sha256':digest,'version':version}))
  go=toolchain(agent,arch)
  env={**os.environ,'CGO_ENABLED':'0','GOMAXPROCS':'1','GOGC':'30','GOTOOLCHAIN':'auto','GOPROXY':'https://proxy.golang.org','GOSUMDB':'sum.golang.org','GOPATH':str(agent/'go-cache'),'GOCACHE':str(agent/'build-cache'),'GOROOT':str(go.parent.parent)}
  output=pathlib.Path(tmp)/'built-hyperdns'
  subprocess.run([str(go),'build','-p','1','-trimpath','-o',str(output),'./cmd/hyperdns'],cwd=root,env=env,check=True,timeout=3600)
  with tarfile.open(agent/'candidate-source.tar.gz','w:gz') as archive:archive.add(root,arcname='Alirezadns-source')
  return output.read_bytes()
ALIREZADNS_3EB154DCE7BCC64001BD5567

if [[ -f "$MANAGER/node.json" ]]; then
 ALIREZADNS_HOST=$(python3 -c 'import json; print(json.load(open("/opt/alirezadns-manager/node.json"))["host"])')
 ALIREZADNS_DOMAIN=$(python3 -c 'import json; print(json.load(open("/opt/alirezadns-manager/node.json"))["domain"])')
fi
if [[ -z "${ALIREZADNS_HOST:-}" ]]; then read -r -p 'Public server IPv4: ' ALIREZADNS_HOST </dev/tty; fi
if [[ -z "${ALIREZADNS_DOMAIN:-}" ]]; then read -r -p 'Domain pointing to this IPv4 (e.g. dns.example.com): ' ALIREZADNS_DOMAIN </dev/tty; fi
export ALIREZADNS_HOST ALIREZADNS_DOMAIN
export ALIREZADNS_EMAIL="${ALIREZADNS_EMAIL:-}"
python3 -c 'import json,os; print(json.dumps({"host":os.environ["ALIREZADNS_HOST"].strip(),"domain":os.environ["ALIREZADNS_DOMAIN"].strip().lower(),"email":os.environ["ALIREZADNS_EMAIL"]}))' > "$STAGE/input.json"
if ! python3 "$STAGE/agent.py" --install < "$STAGE/input.json" > "$STAGE/result.json"; then
 cat "$STAGE/result.json" >&2
 echo 'Installation did not complete. Existing independent services were not removed. Inspect journalctl -u hyperdns.' >&2
 exit 1
fi
python3 "$MANAGER/agent.py" --info
echo 'Initial password only; after changing it, use your new password. Keep the source/license download available.'

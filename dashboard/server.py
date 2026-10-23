"""Local-only dashboard API and background scanner jobs. No LLM integration."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from threading import Lock
from urllib.parse import urlsplit, unquote
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pipeline.scan import ast_heuristic_analyzer, nuclei_runner, secrets_runner, semgrep_runner, zap_runner
from pipeline.scan.common import ScanError, local_url, repo_directory, run_command, tool_environment
from pipeline.scan.run_scan import consolidate
from pipeline.report.report_builder import json_report, pdf_report

TOOLS = [('semgrep', 'Semgrep', semgrep_runner.scan), ('ast', 'Python AST', ast_heuristic_analyzer.scan),
         ('gitleaks', 'Gitleaks', secrets_runner.scan), ('nuclei', 'Nuclei', nuclei_runner.scan), ('zap', 'OWASP ZAP', zap_runner.scan)]
TERMINAL = {'completed', 'partial', 'failed', 'interrupted'}


def now():
    return datetime.now(timezone.utc).isoformat()


def available_tools():
    def exists(variable, binary):
        path = os.environ.get(variable, binary)
        return bool(shutil.which(path))
    readiness = {'ast': True, 'semgrep': exists('SEMGREP_BIN','semgrep'),
                 'gitleaks': exists('GITLEAKS_BIN','gitleaks'), 'nuclei': exists('NUCLEI_BIN','nuclei'),
                 'zap': exists('ZAP_BIN','zap-baseline.py') or exists('ZAP_CLI_BIN','zap.sh')}
    docker = exists('DOCKER_BIN','docker')
    return [{'id': key, 'name': name, 'available': readiness[key],
             'note': ('Docker fallback requires a running daemon and ZAP image' if key == 'zap' and not readiness[key] and docker else
                      'Ready' if readiness[key] else 'Executable not found'),
             'mode': 'static' if key in {'semgrep','ast','gitleaks'} else 'dynamic'} for key,name,_ in TOOLS]


def validate_target(kind, target):
    if not isinstance(target, str) or not target.strip() or len(target) > 2048:
        raise ScanError('Enter a target of at most 2,048 characters.')
    target = target.strip()
    if kind == 'website':
        if '://' not in target:
            if target == '::1': target = '[::1]'
            target = 'http://' + target
        return local_url(target)
    if kind == 'github':
        match = re.fullmatch(r'(?:https://)?github\.com/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9_.-]+)/?', target)
        if not match:
            raise ScanError('Use a public GitHub repository URL: https://github.com/owner/repository. Branch URLs and credentials are not supported.')
        owner, repo = match.groups()
        if repo.endswith('.git'): repo = repo[:-4]
        if not repo or repo in {'.','..'}:
            raise ScanError('Enter a valid GitHub repository name.')
        return f'https://github.com/{owner}/{repo}.git'
    if kind == 'local':
        path = Path(target).expanduser()
        return str(repo_directory(path if path.is_absolute() else ROOT / path))
    raise ScanError('Choose Website / IP, GitHub repository, or Local project.')


class ScanStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        self.lock = Lock()
        self.jobs = {}
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='vibeshield')
        for path in self.directory.glob('*.json'):
            try:
                job = json.loads(path.read_text())
                if job['status'] not in TERMINAL:
                    job['status'] = 'interrupted'; job['finished_at'] = now()
                    job['errors'].append({'source_tool':'orchestrator','error':'The dashboard stopped before this scan completed. Run a new scan.'})
                    for stage in job['stages']:
                        if stage['status'] in {'queued','running'}: stage['status'] = 'interrupted'
                    self.persist(job)
                self.jobs[job['id']] = job
            except (ValueError, KeyError, OSError):
                continue

    def persist(self, job):
        dest = self.directory / (job['id'] + '.json')
        temp = dest.with_suffix('.tmp')
        temp.write_text(json.dumps(job, ensure_ascii=False, indent=2)); temp.replace(dest)

    def get(self, job_id):
        with self.lock:
            return deepcopy(self.jobs.get(job_id))

    def list(self):
        with self.lock:
            return [deepcopy(j) for j in sorted(self.jobs.values(),key=lambda j:j['created_at'],reverse=True)]

    def change(self, job_id, update):
        with self.lock:
            update(self.jobs[job_id]); self.persist(self.jobs[job_id])

    def create(self, body):
        if body.get('authorized') is not True:
            raise ScanError('Confirm that you own the target or have permission to test it.')
        kind = body.get('target_type')
        target = validate_target(kind, body.get('target'))
        selected = TOOLS[3:] if kind == 'website' else TOOLS[:3]
        stages = [{'id':key,'name':name,'status':'queued','finding_count':0} for key,name,_ in selected]
        if kind == 'github': stages.insert(0, {'id':'checkout','name':'GitHub checkout','status':'queued','finding_count':0})
        job = {'id':uuid.uuid4().hex[:12], 'target':target, 'target_type':kind,
               'status':'queued', 'created_at':now(), 'started_at':None, 'finished_at':None,
               'authorization':{'confirmed':True,'confirmed_at':now(),'scope':'local website or authorized static repository'},
               'stages':stages,'findings':[],'errors':[], 'repository_commit':None}
        with self.lock:
            if sum(j['status'] not in TERMINAL for j in self.jobs.values()) >= 5:
                raise ScanError('Five scans are already queued or running. Wait for one to finish.')
            self.jobs[job['id']] = job; self.persist(job)
        self.executor.submit(self.execute, job['id'])
        return self.get(job['id'])

    def stage(self, job_id, key, **values):
        def update(job):
            next(s for s in job['stages'] if s['id']==key).update(values)
        self.change(job_id, update)

    def execute(self, job_id):
        job = self.get(job_id)
        self.change(job_id, lambda j:j.update(status='running', started_at=now()))
        temp = None
        try:
            target = job['target']
            if job['target_type'] == 'github':
                self.stage(job_id,'checkout',status='running',started_at=now())
                temp = tempfile.TemporaryDirectory(prefix='vibeshield-repo-')
                checkout = Path(temp.name) / 'repository'
                env = tool_environment(); env['GIT_TERMINAL_PROMPT']='0'; env['GIT_CONFIG_NOSYSTEM']='1'
                # Do not use user Git configuration, credential helpers, hooks, or submodules.
                env['GIT_CONFIG_GLOBAL']=os.devnull
                git = os.environ.get('GIT_BIN','git')
                run_command([git,'-c','core.hooksPath='+os.devnull,'-c','credential.helper=',
                             '-c','protocol.file.allow=never','clone','--depth','1','--no-tags','--single-branch',target,str(checkout)],120,env=env)
                size = sum(p.stat().st_size for p in checkout.rglob('*') if p.is_file() and not p.is_symlink())
                if size > 200 * 1024 * 1024:
                    raise ScanError('Checkout exceeds the 200 MiB analysis limit.')
                commit = run_command([git,'-C',str(checkout),'rev-parse','HEAD'],15,env=env).stdout.strip()
                self.change(job_id,lambda j:j.update(repository_commit=commit))
                self.stage(job_id,'checkout',status='completed',finished_at=now())
                target = str(checkout)
            selected = TOOLS[3:] if job['target_type']=='website' else TOOLS[:3]
            for key,name,runner in selected:
                self.stage(job_id,key,status='running',started_at=now())
                try:
                    diagnostic = None
                    try:
                        raw = runner(target, timeout=300)
                    except ScanError as exc:
                        raw = exc.findings
                        diagnostic = exc
                    findings = [asdict(consolidate(f)) for f in raw]
                    for item in findings:
                        if job['target_type'] != 'website':
                            for container,field in [(item,'file_or_endpoint'),(item['details'],'file')]:
                                value = container.get(field,'')
                                try: container[field] = str(Path(value).relative_to(target))
                                except ValueError: pass
                    def update(j):
                        j['findings'].extend(findings)
                    self.change(job_id,update)
                    self.stage(job_id,key,status='completed',finding_count=len(findings),finished_at=now())
                    if diagnostic is not None:
                        raise diagnostic
                except (ScanError, OSError) as exc:
                    message = str(exc)
                    self.stage(job_id,key,status='failed',error=message,finished_at=now())
                    self.change(job_id,lambda j:j['errors'].append({'source_tool':key,'error':message}))
            current = self.get(job_id)
            completed = [s for s in current['stages'] if s['status']=='completed' and s['id']!='checkout']
            status = 'completed' if not current['errors'] else 'partial' if completed else 'failed'
            self.change(job_id,lambda j:j.update(status=status,finished_at=now()))
        except Exception as exc:
            # Unexpected exceptions are a failure, never a completed empty scan.
            message = str(exc) if isinstance(exc,(ScanError,OSError)) else 'Unexpected scanner error. Check the local server log.'
            if not isinstance(exc,(ScanError,OSError)):
                print(f'Scan {job_id}: {type(exc).__name__}', file=sys.stderr)
            def fail(j):
                j.update(status='failed',finished_at=now())
                j['errors'].append({'source_tool':'orchestrator','error':message})
                for stage in j['stages']:
                    if stage['status']=='running': stage.update(status='failed',error=message)
                    elif stage['status']=='queued': stage['status']='skipped'
            self.change(job_id,fail)
        finally:
            if temp: temp.cleanup()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store, web_root):
        self.store=store; self.web_root=Path(web_root).resolve(); self.csrf=secrets.token_urlsafe(32)
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = 'VibeShield/1.0'
    def log_message(self, fmt, *args):
        if '/api/' not in self.path: super().log_message(fmt,*args)

    def trusted(self):
        host = self.headers.get('Host','')
        allowed = {f'localhost:{self.server.server_port}',f'127.0.0.1:{self.server.server_port}'}
        if host not in allowed: return False
        origin = self.headers.get('Origin')
        return not origin or origin in {'http://'+h for h in allowed}

    def send(self, status, data, content_type='application/json', filename=None):
        if not isinstance(data, bytes): data=json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type',content_type); self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer'); self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if filename: self.send_header('Content-Disposition',f'attachment; filename="{filename}"')
        self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        if not self.trusted(): return self.send(403,{'error':'Only same-origin localhost access is allowed.'})
        path = urlsplit(self.path).path
        if path == '/api/status':
            return self.send(200,{'tools':available_tools(),'csrf_token':self.server.csrf,'scope':'local-only',
                                  'fixture_path':'fixtures/idor-notes-app','fixture_url':'http://127.0.0.1:5000/api/health',
                                  'git_available':bool(shutil.which(os.environ.get('GIT_BIN','git'))),
                                  'pdf_available':__import__('importlib.util',fromlist=['util']).find_spec('reportlab') is not None})
        if path == '/api/documentation.pdf':
            document = ROOT / 'docs' / 'VibeShield_Project_Documentation.pdf'
            if not document.is_file(): return self.send(404, {'error': 'Project documentation has not been generated.'})
            return self.send(200, document.read_bytes(), 'application/pdf', document.name)
        if path == '/api/scans': return self.send(200,{'scans':self.server.store.list()})
        match = re.fullmatch(r'/api/scans/([a-f0-9]{12})(?:/report\.(pdf|json))?',path)
        if match:
            job = self.server.store.get(match[1])
            if not job: return self.send(404,{'error':'Scan not found.'})
            if match[2]:
                if job['status'] not in TERMINAL: return self.send(409,{'error':'The scan is still running. Reports are available when it finishes.'})
                try: content = pdf_report(job) if match[2]=='pdf' else json_report(job)
                except ImportError: return self.send(503,{'error':'PDF rendering is unavailable. Install dashboard/requirements.txt or download JSON.'})
                return self.send(200,content,'application/pdf' if match[2]=='pdf' else 'application/json',f'vibeshield-{job["id"]}.{match[2]}')
            return self.send(200,job)
        if path.startswith('/api/'): return self.send(404,{'error':'API route not found.'})
        relative = unquote(path).lstrip('/') or 'index.html'
        file = (self.server.web_root / relative).resolve()
        if not file.is_relative_to(self.server.web_root): return self.send(404,{'error':'Not found.'})
        if not file.is_file():
            if '.' in Path(relative).name: return self.send(404,{'error':'Not found.'})
            file = self.server.web_root/'index.html'
        if not file.is_file(): return self.send(503,{'error':'Build the dashboard first: cd dashboard/web && npm run build'})
        self.send(200,file.read_bytes(),mimetypes.guess_type(file.name)[0] or 'application/octet-stream')

    def do_POST(self):
        if not self.trusted() or not secrets.compare_digest(self.headers.get('X-VibeShield-Token',''),self.server.csrf):
            return self.send(403,{'error':'Session verification failed. Refresh the page and try again.'})
        if self.path != '/api/scans': return self.send(404,{'error':'API route not found.'})
        try:
            length = int(self.headers.get('Content-Length','0'))
            if length < 1 or length > 8192: return self.send(413,{'error':'Request must contain a small JSON scan target.'})
            body = json.loads(self.rfile.read(length))
            if not isinstance(body,dict): raise ValueError()
            return self.send(202,self.server.store.create(body))
        except (ValueError, UnicodeError): return self.send(400,{'error':'Invalid JSON request.'})
        except ScanError as exc: return self.send(400,{'error':str(exc)})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8787)
    parser.add_argument('--data-dir',default=str(ROOT/'.vibeshield'/'scans'))
    args=parser.parse_args()
    server=DashboardServer(('127.0.0.1',args.port),ScanStore(args.data_dir),ROOT/'dashboard'/'web'/'dist')
    print(f'VibeShield dashboard: http://127.0.0.1:{args.port}',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close(); server.store.executor.shutdown(wait=False,cancel_futures=True)


if __name__=='__main__': main()

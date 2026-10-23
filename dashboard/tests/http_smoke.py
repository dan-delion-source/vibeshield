"""Local API smoke checks; requires the dashboard on port 8787."""
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError
base='http://127.0.0.1:8787'
with urlopen(base+'/api/status') as r: status=json.load(r)
def post(body, token):
    request=Request(base+'/api/scans',json.dumps(body).encode(),headers={'Content-Type':'application/json','X-VibeShield-Token':token})
    try:
        with urlopen(request) as r: return r.status
    except HTTPError as e: return e.code
assert post({'target_type':'website','target':'https://example.com','authorized':True},status['csrf_token'])==400
assert post({'target_type':'website','target':'localhost:5000','authorized':True},'invalid')==403
with urlopen(base+'/api/documentation.pdf') as r: assert r.read(5)==b'%PDF-'
print('HTTP target rejection, CSRF rejection, and project PDF download passed.')

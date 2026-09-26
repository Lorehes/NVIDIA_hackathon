"""VM-only live regression; store public test results and effective policy pins."""
import ipaddress
import json
import subprocess
import time
from pathlib import Path
import httpx


def policies():
    p = subprocess.run(['openshell', 'policy', 'get', 'my-assistant', '--full', '-o', 'json'],
                       capture_output=True, text=True, timeout=20)
    p.check_returncode()
    data = json.loads(p.stdout)
    assert data['status'] == 'effective'
    return {name: policy for name, policy in data['policy']['network_policies'].items()
            if name.startswith('job-') or name.startswith('nemoclaw_custom__job-')}


def main():
    output = []
    client = httpx.Client(base_url='http://127.0.0.1:8000', timeout=30,
                          headers={'x-session-id': 'validation-discovered-navigation-20260925'})
    for _ in range(30):
        try:
            if client.get('/api/health').status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(2)
    for url in ['https://naver.com/', 'https://www.naver.com/', 'https://m.naver.com/', 'https://mail.naver.com/']:
        r = client.post('/api/investigations', json={'input': url, 'mode': 'live'})
        r.raise_for_status()
        job_id = r.json()['job_id']
        print('started', url, job_id, flush=True)
        snapshots, seen = [], set()
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            v = client.get('/api/investigations/' + job_id).json()
            hosts = tuple(v.get('open_hosts', []))
            if hosts and hosts not in seen:
                seen.add(hosts)
                applied = policies()
                for name, policy in applied.items():
                    if job_id.replace('_', '-') not in name:
                        continue
                    endpoints = policy.get('endpoints', [])
                    snapshots.append({'name': name, 'endpoints': endpoints})
                    assert endpoints and all(e.get('allowed_ips') for e in endpoints), 'effective pins missing'
                    assert all(ipaddress.ip_address(ip).is_global for e in endpoints for ip in e['allowed_ips'])
            if v.get('status') in ('done', 'failed'):
                break
            time.sleep(2)
        else:
            raise TimeoutError(job_id)
        trace = client.get('/api/investigations/' + job_id + '/trace').json()
        result = v.get('result') or {}
        row = {'url': url, 'job_id': job_id, 'status': v['status'], 'result': result,
               'timings': v.get('timings_ms'), 'policy_snapshots': snapshots, 'trace': trace,
               'residual_policies': [n for n in policies() if job_id.replace('_', '-') in n]}
        output.append(row)
        Path('/tmp/discovered-navigation-live.json').write_text(json.dumps(output, ensure_ascii=False, indent=2))
        print(json.dumps({'url': url, 'status': v['status'], 'verdict': result.get('verdict'),
                          'incomplete': result.get('incomplete_reason'), 'chain': result.get('redirect_chain'),
                          'pins_seen': len(snapshots), 'residual': row['residual_policies']}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()

import yaml
with open('docker-compose.yml') as f: d = yaml.safe_load(f)
for s in d['services'].values():
    if 'command' not in s: s['command'] = 'tail -f /dev/null'
    s.setdefault('volumes', []).append('./config/resolv.conf:/etc/resolv.conf:ro')
with open('docker-compose.yml', 'w') as f: yaml.dump(d, f)

import yaml
with open('docker-compose.yml') as f: d = yaml.safe_load(f)

# local-dns -> bind8-base, uses named.boot
d['services']['local-dns']['build'] = './bind8'
d['services']['local-dns']['image'] = 'bind8-base'
d['services']['local-dns']['command'] = '/bin/bash -c "named -b /etc/bind/named.boot && tail -f /dev/null"'

# attacker and victim run tail -f
d['services']['attacker']['command'] = 'tail -f /dev/null'
d['services']['victim']['command'] = 'tail -f /dev/null'

with open('docker-compose.yml', 'w') as f: yaml.dump(d, f)
with open('docker-compose.yml') as f: d = yaml.safe_load(f)
d['services']['local-dns'].setdefault('volumes', []).append('./config/resolv.conf:/etc/resolv.conf:ro')
with open('docker-compose.yml', 'w') as f: yaml.dump(d, f)

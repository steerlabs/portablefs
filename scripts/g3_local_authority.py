"""Select the VZ host-local NAT bridge without external-interface discovery."""
import ipaddress
import json
import re
import subprocess


def local_endpoint(guest, published_port):
    routes=json.loads(guest.ssh('ip -4 -j route show default'))
    gateways={r['gateway'] for r in routes if 'gateway' in r}
    assert len(gateways)==1, routes
    gateway=gateways.pop()
    address=ipaddress.ip_address(gateway)
    assert address.is_private and not address.is_loopback and not address.is_unspecified, gateway
    interfaces=subprocess.check_output(['/sbin/ifconfig','-a'],text=True)
    blocks=re.split(r'(?m)^(?=\S+?: flags=)',interfaces)
    matches=[block.split(':',1)[0] for block in blocks
             if block.startswith(('bridge','vmenet')) and re.search(r'(?m)^\s+inet '+re.escape(gateway)+r'\s',block)]
    assert len(matches)==1, 'VZ gateway must belong to a host-local virtual bridge'
    return gateway+':'+str(published_port),matches[0]

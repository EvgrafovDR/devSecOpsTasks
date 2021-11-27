import psutil
from scapy.layers.inet import IP
from scapy.sendrecv import sniff
from scapy.utils import wrpcap


def handle_packet(packet):
    if packet.haslayer("TCP"):
        print("%s:%d\t->\t%s:%d" % (packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport))
        wrpcap("dumps/sniffer.pcap", packet, append=True)


def start_sniffer(iface, port):
    sniff(iface=iface, filter='dst port %d || src port %d' % (port, port), prn=handle_packet)


def dialog():
    addresses = psutil.net_if_addrs()
    ifaces = list(addresses.keys())
    print("Detected interfaces:")
    number = 1
    for iface in ifaces:
        print("%d. %s" % (number, iface))
        number += 1
    iface_number = int(input("Choose interface [%d-%d]:" % (1, number - 1)))
    choosen_iface = ifaces[iface_number]
    port = int(input("Enter sniffed port:"))
    start_sniffer(choosen_iface, port)


if __name__ == "__main__":
    dialog()
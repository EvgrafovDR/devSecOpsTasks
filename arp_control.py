
# load configuration
import configparser
import time

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sniff
from scapy.utils import wrpcap

from arp_table import ArpTable


class ArpScanner:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read("configs/main.ini")
        self._network = config.get('network', 'network')
        assert isinstance(self._network, str), 'example 192.168.0.0/24'
        self._iface = config.get('network', 'iface', fallback=None)
        self._pcap_folder = config.get('main', 'pcap_folder', fallback=None)
        self._log_folder = config.get('main', 'log_folder', fallback=None)
        self._arp_table = ArpTable()

    # method to scan network configuration and create IP-MAC-HOST table
    def arp_scan(self):
        if self._iface is not None:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self._network), iface=self._iface, timeout=5, verbose=False)
        else:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self._network), timeout=5, verbose=False)
        for pkt in ans:
            ip = pkt[1].psrc
            mac = pkt[1].src
            arp_record = self._arp_table.get_record(self._network, ip)
            if arp_record is None:
                event_time = time.strftime("%d-%m-%Y %H.%M.%S", time.localtime())
                self._arp_table.add_record(self._network, mac, ip)
                print(f'{event_time} host {ip} - {mac} added to arp_table')

    def arp_filter(self):
        if self._iface is not None:
            sniff(iface=self._iface, filter='arp', prn=self._arp_handler)
        else:
            sniff(filter='arp', prn=self._arp_handler)

    def _arp_handler(self, pkt):
        ip = pkt.psrc
        mac = pkt.src
        event_time = time.strftime("%d-%m-%Y %H.%M.%S", time.localtime())
        arp_record = self._arp_table.get_record(self._network, ip)
        if arp_record is None:
            self._arp_table.add_record(self._network, mac, ip)
            print(f'{event_time} new host detected {ip} - {mac} added to arp_table')
        elif arp_record != mac:
            if self._pcap_folder is not None:
                wrpcap(self._pcap_folder + f'{time.localtime().tm_mday}_arp_alert.pcap', pkt, append=True)
            if self._log_folder is not None:
                with open(self._log_folder + 'arp.log', 'a') as log:
                    log.write(f'{event_time} {ip} alert ARP-spoofing detected from {mac}')

            print(f'{event_time} {ip} alert ARP-spoofing detected from {mac}')


if __name__ == "__main__":
    scanner = ArpScanner()
    scanner.arp_scan()
    scanner.arp_filter()

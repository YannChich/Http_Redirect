import random
from scapy.all import *
from scapy.layers.dhcp import BOOTP_am, DHCP_am, DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

conf.checkIPaddr = False

# Variables à personnaliser
iface = "eth0"
dhcp_server_ip = "192.168.1.1"
subnet_mask = "255.255.255.0"
router_ip = "192.168.1.254"
dns_ip = "8.8.8.8"
ip_range_start = "192.168.1.100"
ip_range_end = "192.168.1.200"
lease_time = 86400  # 24 heures en secondes

# Table d'attribution d'adresse IP
ip_allocations = {}


def handle_dhcp_packet(packet):
    if DHCP in packet:
        dhcp_options = packet[DHCP].options
        dhcp_message_type = None

        for option in dhcp_options:
            if option[0] == "message-type":
                dhcp_message_type = option[1]
                break

        if dhcp_message_type == 1:  # DHCP Discover
            print("DHCP Discover reçu")
            send_dhcp_offer(packet)
        elif dhcp_message_type == 3:  # DHCP Request
            print("DHCP Request reçu")
            send_dhcp_ack(packet)


def send_dhcp_offer(discover_packet):
    global ip_allocations

    offered_ip = generate_ip()

    if offered_ip is None:
        return

    mac_address = discover_packet[Ether].src
    transaction_id = discover_packet[BOOTP].xid
    ip_allocations[mac_address] = offered_ip

    dhcp_offer = (
            Ether(src=get_if_hwaddr(iface), dst=mac_address) /
            IP(src=dhcp_server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, htype=1, hlen=6, xid=transaction_id, yiaddr=offered_ip, siaddr=dhcp_server_ip,
                  chaddr=mac_address) /
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", dhcp_server_ip),
                ("lease_time", lease_time),
                ("subnet_mask", subnet_mask),
                ("router", router_ip),
                ("name_server", dns_ip),
                "end"
            ])
    )

    sendp(dhcp_offer, iface=iface, verbose=False)
    print(f"DHCP Offer envoyé pour l'adresse {offered_ip}")


def send_dhcp_ack(request_packet):
    global ip_allocations

    mac_address = request_packet[Ether].src
    transaction_id = request_packet[BOOTP].xid
    requested_ip = ip_allocations.get(mac_address, None)

    if requested_ip is None:
        return

    dhcp_ack = (
            Ether(src=get_if_hwaddr(iface), dst=mac_address) /
            IP(src=dhcp_server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, htype=1, hlen=6, xid=transaction_id, yiaddr=requested_ip, siaddr=dhcp_server_ip,
                  chaddr=mac_address) /
            DHCP(options=[
                ("message-type", "ack"),
                ("server_id", dhcp_server_ip),
                ("lease_time", lease_time),
                ("subnet_mask", subnet_mask),
                ("router", router_ip),
                ("name_server", dns_ip),
                "end"
            ])
    )

    sendp(dhcp_ack, iface=iface, verbose=False)
    print(f"DHCP ACK envoyé pour l'adresse {requested_ip}")


def generate_ip():
    global ip_allocations

    ip_range = list(map(int, ip_range_start.split('.'))), list(map(int, ip_range_end.split('.')))
    for i in range(ip_range[0][3], ip_range[1][3] + 1):
        candidate_ip = f"{ip_range[0][0]}.{ip_range[0][1]}.{ip_range[0][2]}.{i}"
        if candidate_ip not in ip_allocations.values():
            return candidate_ip
    return None


def main():
    print("Démarrage du serveur DHCP...")
    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp_packet, iface=iface, store=0)


if __name__ == "main":
    main()

import socket

import dns
from dns import resolver
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


# DHCP vars.
dhcp_server_ip = "192.168.20.20"

# DNS var.y
dns_server_ip = "127.0.0.1"
dns_port = 53
domain_to_resolve = 'WhyTalIsGay.com'

# DHCP Discover
def send_dhcp_discover():
    dhcp_discover = (
        Ether(src=get_if_hwaddr(conf.iface), dst='ff:ff:ff:ff:ff:ff') /
        IP(src='0.0.0.0', dst='255.255.255.255') /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=get_if_raw_hwaddr(conf.iface)[1]) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(dhcp_discover, verbose=True)
    print("DHCP Discover sent.")

def send_dhcp_request(offered_ip):
    dhcp_request = (
        Ether(src=get_if_hwaddr(conf.iface), dst='ff:ff:ff:ff:ff:ff') /
        IP(src='0.0.0.0', dst='255.255.255.255') /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=get_if_raw_hwaddr(conf.iface)[1]) /
        DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", offered_ip),
            ("server_id", dhcp_server_ip),
            "end"
        ])
    )
    sendp(dhcp_request, verbose=True)
    print("DHCP Request sent.")



# Receive response - DHCP Offer
def handle_dhcp_offer(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 2:
        offered_ip = packet[BOOTP].yiaddr
        print(f"IP address offered: {offered_ip}")
        send_dhcp_request(offered_ip)  # Call the send_dhcp_request function here
        return offered_ip
    else:
        return None


import subprocess


def handle_dhcp_ack(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 5:
        acked_ip = packet[BOOTP].yiaddr
        print(f"IP address acknowledged: {acked_ip}")

        # Set IP address on the interface
        interface_name = conf.iface
        subnet_mask = "255.255.255.0"
        set_ip_command = f"sudo ifconfig {interface_name} {acked_ip} netmask {subnet_mask}"
        subprocess.run(set_ip_command, shell=True, check=True)

        return acked_ip
    else:
        return None


# DNS req sending
# Envoyer une requête DNS
def send_dns_query(dns_server_ip, domain):
    query = dns.message.make_query(domain, dns.rdatatype.A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query.to_wire(), (dns_server_ip, 53))
    response_data, server_address = sock.recvfrom(1024)  # Fix here
    response = dns.message.from_wire(response_data)
    return response

# Extraire l'adresse IP du résultat DNS
def extract_dns_response_ip(response):
    if response:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    resolved_ip = rdata.to_text()
                    return resolved_ip
    return None


def main():
    # Receiving IP address using DHCP.
    send_dhcp_discover()
    dhcp_offer = sniff(filter="udp and (port 67 or port 68)", count=1, timeout=60, prn=handle_dhcp_offer)
    if not dhcp_offer:
        print("Did not receive DHCP response.")
        return

    dhcp_ack = sniff(filter="udp and (port 67 or port 68)", count=1, timeout=60, prn=handle_dhcp_ack)
    if not dhcp_ack:
        print("Did not receive DHCP ACK.")
        return

    # Sending DNS request and print the domain.
    print(f"Sending DNS request for the domain: {domain_to_resolve}")
    dns_response = send_dns_query(dns_server_ip, domain_to_resolve)
    resolved_ip = extract_dns_response_ip(dns_response)

    if resolved_ip:
        print(f"The domain {domain_to_resolve} has been resolved to {resolved_ip}")
    else:
        print(f"The domain {domain_to_resolve} could not be resolved.")



if __name__ == "__main__":
    main()

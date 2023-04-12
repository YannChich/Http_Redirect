import socket
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


# Variables pour le serveur DHCP
dhcp_server_ip = "192.168.1.1"

# Variables pour le serveur DNS
dns_server_ip = '127.0.0.1'
dns_port = 53
domain_to_resolve = 'example.com'

# Envoyer une requête DHCP Discover
def send_dhcp_discover():
    dhcp_discover = (
        Ether(src=get_if_hwaddr(conf.iface), dst='ff:ff:ff:ff:ff:ff') /
        IP(src='0.0.0.0', dst='255.255.255.255') /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=get_if_raw_hwaddr(conf.iface)[1]) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(dhcp_discover, verbose=False)
    print("DHCP Discover envoyé")


# Recevoir une réponse DHCP Offer
def handle_dhcp_offer(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 2:
        offered_ip = packet[BOOTP].yiaddr
        print(f"Adresse IP attribuée: {offered_ip}")
        return offered_ip
    else:
        return None


# Envoyer une requête DNS
def send_dns_query(dns_server_ip, domain):
    query = IP(dst=dns_server_ip) / UDP(dport=dns_port) / DNS(rd=1, qd=DNSQR(qname=domain))
    response = sr1(query, verbose=False)
    return response


# Extraire l'adresse IP du résultat DNS
def extract_dns_response_ip(response):
    if response and DNS in response:
        for i in range(response[DNS].ancount):
            if response[DNS].an[i].type == 1:
                resolved_ip = response[DNS].an[i].rdata
                return resolved_ip
    return None


def main():
    # Obtenir une adresse IP à l'aide du serveur DHCP
    send_dhcp_discover()
    dhcp_offer = sniff(filter="udp and (port 67 or port 68)", count=1, timeout=10, prn=handle_dhcp_offer)
    if not dhcp_offer:
        print("Aucune réponse DHCP Offer reçue.")
        return

    # Envoyer une requête DNS et afficher l'adresse IP résolue
    print(f"Envoi de la requête DNS pour le domaine {domain_to_resolve}")
    dns_response = send_dns_query(dns_server_ip, domain_to_resolve)
    resolved_ip = extract_dns_response_ip(dns_response)

    if resolved_ip:
        print(f"Le domaine {domain_to_resolve} a été résolu en {resolved_ip}")
    else:
        print(f"Le domaine {domain_to_resolve} n'a pas été résolu.")


if __name__ == "__main__":
    main()

from scapy.all import *
import time
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether


# Project Vars.
dhcp_ip = "10.20.30.40"
ip_range_start = "10.20.30.41"
ip_range_end = "10.20.30.100"
router_ip = "10.20.30.101"
subnet_mask = "255.255.255.0"
ip_allocs = 0




# Genarate an IP address.
def generate_ip():
    num = ip_range_end.split(".")
    global ip_allocs
    while ip_allocs < int(num[-1]):
        # Split the IP address string into an array
        ip_array = ip_range_start.split(".")
        # Increment the last element in the array
        ip_array[-1] = str(int(ip_array[-1]) + ip_allocs)
        ip_allocs += 1
        # Reassemble the array back into a string
        incremented_ip = ".".join(ip_array)
        return incremented_ip
    print("You dont have any other IPs to provide.")
    return None


# DHCP requests handler function.
def discover_to_offer(packet,offer_client_ip):

    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print("[+] Got DHCP Discover.")

        dhcp_offer = (Ether(src=get_if_hwaddr("ens33"), dst=packet[Ether].src) /
                      IP(src=dhcp_ip, dst="255.255.255.255") /
                      UDP(sport=67, dport=68) /
                      BOOTP(op=2, yiaddr=offer_client_ip, siaddr="10.20.30.40", chaddr=packet[Ether].src)/
                      DHCP(options=[("message-type", "offer"),
                                  ("server_id", dhcp_ip),
                                  ("subnet_mask", "255.255.255.0"),
                                  ("router", "10.20.30.40"),
                                  ("name_server", "10.20.30.40"),
                                  ("lease_time", 86400),
                                    "end"]))

        print("[+] Responding to client.")
        time.sleep(1)
        sendp(dhcp_offer,verbose=False)
        return offer_client_ip


def request_to_ack(packet,offer_client_ip):

    if DHCP in packet and packet[DHCP].options[0][1] == 3:
        print("[+] Got DHCP Request.")

        dhcp_ack = (Ether(src=get_if_hwaddr("ens33"), dst=packet[Ether].src) /
                    IP(src=dhcp_ip, dst="255.255.255.255") /
                    UDP(sport=67, dport=68) /
                    BOOTP(op=2, yiaddr=packet[BOOTP].yiaddr, siaddr="10.20.30.40", chaddr=packet[Ether].src) /
                    DHCP(options=[("message-type", "ack"),
                                  ("server_id", dhcp_ip),
                                  ("subnet_mask", "255.255.255.0"),
                                  ("router", "10.20.30.40"),
                                  ("name_server", "10.20.30.40"),
                                  ("lease_time", 86400),
                                  "end"]))
                                  
        print("[+] ACK Sent To The Client.")
        # Send DHCP Ack to the client
        time.sleep(1)
        sendp(dhcp_ack,verbose=False)


# main
if __name__ == "__main__":
        while True:
            print("[+] DHCP Server Running.")
            dhcp_packet = sniff(filter="udp and (port 67 or port 68)", count=1, iface="ens33")[0]
            offer_client_ip = discover_to_offer(dhcp_packet,generate_ip())
            packet = sniff(filter="udp and port 67", count=1, iface="ens33")[0]
            request_to_ack(packet,offer_client_ip)

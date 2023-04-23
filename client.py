import dns
import sys
from dns import resolver
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import socket
import threading
import time



# DHCP Server.

client_ip = "0.0.0.0"
dns_server_ip = "127.0.0.3"
domain = "example.com"

#Sending DHCP discover to the server.
def send_dhcp_dis():
    dhcp_packet = (Ether(dst="ff:ff:ff:ff:ff") /
                    IP(src='0.0.0.0', dst='255.255.255.255') /
                    UDP(sport=68, dport=67) /
                    BOOTP(op=1, chaddr=get_if_raw_hwaddr(conf.iface)[1]) /
                    DHCP(options=[("message-type", "discover"), "end"]))
    print("[+] DHCP Discover Sent.")
    sendp(dhcp_packet, verbose=False)


# DHCP offer handler function.
def dhcp_offer(client_ip,packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 2:
        print("[+] Got A DHCP Offer.")
        client_ip = packet[BOOTP].yiaddr
        print("[+] DHCP Server Sent The IP:", client_ip)
        dhcp_packet = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                       IP(src="0.0.0.0", dst="255.255.255.255") /
                       UDP(sport=68, dport=67) /
                       BOOTP(op=1, chaddr=get_if_raw_hwaddr(conf.iface)[1]) /
                       DHCP(options=[("message-type", "request"),
                                     ("requested_addr", packet[BOOTP].yiaddr),
                                     ("server_id", packet[IP].src),
                                     "end"]))
        print("[+] DHCP Request Sent.")
        sendp(dhcp_packet ,verbose=False)
        return client_ip


# Applying the actual DHCP offer.
def got_dhcp_ack(client_ip,packet):

    if DHCP in packet and packet[DHCP].options[0][1] == 5:
        print("[+] DHCP ack received.")
        interface_name = conf.iface
        subnet_mask = "255.255.255.0"
        set_ip_command = f"sudo ifconfig {interface_name} {client_ip} netmask {subnet_mask}"
        subprocess.run(set_ip_command, shell=True, check=True)
        print("[ifconfig] Machine IP set to:",client_ip)

# DNS request sending.
def send_dns_query(dns_server_ip, domain, client_ip=None):
    query = dns.message.make_query(domain, dns.rdatatype.A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if client_ip:
        sock.bind((client_ip, 0))

    sock.sendto(query.to_wire(), (dns_server_ip, 53))
    response_data, server_address = sock.recvfrom(1024)
    response = dns.message.from_wire(response_data)
    return response

# Extracting the IP from DNS.
def extract_dns_response_ip(response):
    if response:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    resolved_ip = rdata.to_text()
                    return resolved_ip
    return None

# RUDP FUNCTIONCS 

def hostname_to_numeric(hostname):
    return sum(ord(c) for c in hostname)

def handle_lost_packet_signal(client, packet_id,sent_packets):
    packet_data = sent_packets.get(packet_id)
    if packet_data:
        print(f"Resending packet {packet_id}: {packet_data}")
        client.sendto(f"SIGNGET:{packet_id};{packet_data}".encode(), (resolved_ip, 49152))

def receive(server,connection_open,sent_packets):
    while True:
        data, addr = server.recvfrom(1024)
        data = data.decode()
        print(f"Received data: {data}")

        if data.startswith("SIGNLOST:"):
            print("Receive SIGNLOST , going to send the lost packet")
            packet_id = int(data.split(":", 1)[1])
            handle_lost_packet_signal(server, packet_id, sent_packets)
        elif data.startswith("ACKEND:"):
            print("Received ACKEND from server. Closing connection.")
            connection_open = False
            server.close()
            sys.exit(0)
        elif data.startswith("ECHOREPLY:"):
            packet_id, timestamp = data.split(":", 1)[1].split(";", 1)
            packet_id = int(packet_id)
            latency = (time.time() - float(timestamp)) * 1000
            print(f"Received ECHOREPLY from server. Latency: {latency:.2f} ms")



def RUDP_Client(hostname):
    connection_open = True
    resolved_ip = "127.0.0.31"
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print(f"Gonna try to connect to {resolved_ip}")
    print(" [RUDP] Sending a SIGNAL : SIGNEW to the RUDP Server")
    client.sendto(f"SIGNEW:{hostname}".encode(), (resolved_ip, 49152))

    sent_packets = {}
    packet_id = hostname_to_numeric(hostname)
    # Ajouter un thread pour écouter les messages entrants du serveur
    receive_thread = threading.Thread(target=receive, args=(client,connection_open,sent_packets))
    receive_thread.daemon = True
    receive_thread.start()

    while True:
        if connection_open == False:
            create_new_connection = input("Connection closed. Do you want to send SIGNEW to create a new connection? (yes/no): ")
            if create_new_connection.lower() == "yes":
                connection_open = True
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                print(" [RUDP] Sending a SIGNAL : SIGNEW to the RUDP Server")
                client.sendto(f"SIGNEW:{hostname}".encode(), (resolved_ip, 49152))
            else:
                print("END OF CONNECTION")
        
        else:
            # input message to let the user what signal is going to be sent
            print("-------------------------------------------------------")
            print("This is the list of signals you can send :")
            print("SIGNGET : to get the ridirection to the server HTTP")
            print("SIGNEND : to end the connection")
            print("SIGNECHO : to know the ping with the server RUDP")
            print("-------------------------------------------------------")

            message = input("SIGNAL :")

            packet_id+=1

            if message == "SIGNGET":
                print(" [RUDP] Sending a SIGNAL : SIGNGET to the RUDP Server")
                client.sendto(f"SIGNGET:{packet_id};{message}".encode(), (resolved_ip, 49152))
                sent_packets[packet_id] = message

            elif message == "SIGNEND":
                print(" [RUDP] Sending a SIGNAL : SIGNEND to the RUDP Server")
                client.sendto(f"SIGNEND:{packet_id};{message}".encode(), (resolved_ip, 49152))
                sent_packets[packet_id] = message
            
            elif message == "SIGNECHO":
                timestamp = time.time()
                print(" [RUDP] Sending a SIGNAL : SIGNECHO to the RUDP Server")
                client.sendto(f"SIGNECHO:{packet_id};{timestamp}".encode(), (resolved_ip, 49152))
                sent_packets[packet_id] = message


            else:
                print("Invalid signal, please try again.")

        

# Main func.
if __name__ == "__main__":

    hostname = input("Enter your name : ")
    # DHCP Block
    # send_dhcp_dis()
    # dhcp_packet = sniff(filter="udp and (port 67 or port 68)", count=1, timeout=10, iface="enp0s3")[0]
    # client_ip = dhcp_offer(client_ip, dhcp_packet)
    # dhcp_packet = sniff(filter="udp and (port 67 or port 68)", count=1, timeout=10, iface="enp0s3")[0]
    # got_dhcp_ack(client_ip, dhcp_packet)
    #
    # print("")
    #
    # # DNS Block
    # print(f"[DNS] Sending DNS request for the domain: {domain}")
    # dns_response = send_dns_query(dns_server_ip, domain, client_ip)
    # resolved_ip = extract_dns_response_ip(dns_response)
    # if resolved_ip:
    #     print(f"[DNS] The domain {domain} has been resolved to {resolved_ip}")
    # else:
    #     print(f"[DNS] The domain {domain} could not be resolved.")
    #
    # print("")
    # RUDP Block
    RUDP_Client(hostname)
    





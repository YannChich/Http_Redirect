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
import subprocess
import sys
import time
import requests
from bs4 import BeautifulSoup
from queue import Queue

# DHCP Server.

client_ip = "127.0.0.6"
dns_server_ip = "127.0.0.7"
domain = "example.com"
resolved_ip = "127.0.0.77"
connection_open = True
pause_client = False
list_queue = Queue()
List = {}

# Downloading files.
def download_file(list):
    i=1
    for i in range(0,len(list)):
        print(f"-{i} : {list[i]}")
        
    while True:
        num = int(input("The number of the file you would like to download: Press 0 if u want to exit "))
        if num == 0:
            print("We are goind to comeback on the connection with the RUDP Server")
            print(".................................................")
            connection_open = True
            break
        if num <= len(list):
            filename = f"{list[num - 1]}"
            set_ip_command = f"wget --bind-address={client_ip} http://localhost/{filename}"
            subprocess.run(set_ip_command, shell=True, check=True)
            set_ip_command = f"sudo chmod 777 {filename}"
            subprocess.run(set_ip_command, shell=True, check=True)
        else:
            print("Wrong file number.")


# Sending DHCP discover to the server.
def send_dhcp_dis():
    dhcp_packet = (Ether(dst="ff:ff:ff:ff:ff") /
                   IP(src='0.0.0.0', dst='255.255.255.255') /
                   UDP(sport=68, dport=67) /
                   BOOTP(op=1, chaddr=get_if_raw_hwaddr(conf.iface)[1]) /
                   DHCP(options=[("message-type", "discover"), "end"]))
    print("[+] DHCP Discover Sent.")
    sendp(dhcp_packet, verbose=False)


# DHCP offer handler function.
def dhcp_offer(client_ip, packet):
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
        sendp(dhcp_packet, verbose=False)
        return client_ip


# Applying the actual DHCP offer.
def got_dhcp_ack(client_ip, packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 5:
        print("[+] DHCP ack received.")
        interface_name = conf.iface
        subnet_mask = "255.255.255.0"
        set_ip_command = f"sudo ifconfig {interface_name} {client_ip} netmask {subnet_mask}"
        subprocess.run(set_ip_command, shell=True, check=True)
        print("[ifconfig] Machine IP set to:", client_ip)


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


def handle_lost_packet_signal(client, packet_id, sent_packets):
    packet_data = sent_packets.get(packet_id)
    print("-----------------------------------------------")
    print(f"Resending packet {packet_id}: {packet_data}")
    print("-----------------------------------------------")
    if packet_data == "SIGNGET":
        client.sendto(f"SIGNGET:{packet_id};{packet_data}".encode(), (resolved_ip, 49152))
    if packet_data == "SIGNECHO":
        client.sendto(f"SIGNECHO:{packet_id};{packet_data}".encode(), (resolved_ip, 49152))
    if packet_data == "SIGNSTAT":
        client.sendto(f"SIGNSTAT:{packet_id};{packet_data}".encode(), (resolved_ip, 49152))
    else:
        client.sendto(f"SIGNEND:{packet_id};{packet_data}".encode(), (resolved_ip, 49152))

    

def handle_ackget(data):
    global connection_open
    packet_id, file_list = data.split(":", 1)[1].split(";", 1)
    my_list = file_list.split(";")[:-1]  # Remove the last empty element
    list_queue.put(my_list)
    connection_open = False

    


def receive(server, sent_packets):
    global connection_open
    global pause_client
    while True:
        data, addr = server.recvfrom(1024)
        data = data.decode()
        print(f"Received data: {data}")

        if data.startswith("SIGNACK"):
            print("Receive ACK from the RUDP Server.")

        elif data.startswith("SIGNLOST:"):
            print("Receive SIGNLOST , going to send the lost packet")
            packet_id = int(data.split(":", 1)[1])
            handle_lost_packet_signal(server, packet_id, sent_packets)

        elif data.startswith("ACKGET:"):
            print("Received ACKGET from server")
            handle_ackget(data)
            connection_open = False
            

        elif data.startswith("ACKEND:"):
            print("Received ACKEND from server. Closing connection.")
            connection_open = False
            server.close()
            sys.exit(0)

        elif data.startswith("ECHOREPLY:"):
            packet_id, timestamp = data.split(":", 1)[1].split(";", 1)
            latency = (time.time() - float(timestamp)) * 1000
            print(f"Received ECHOREPLY from server. Latency: {latency:.2f} ms")

        elif data.startswith("STATREPLY:"):
            packet_id, stats = data.split(":", 1)[1].split(";", 1)
            print(f"Received STATREPLY from server. Server statistics:\n{stats}")

        elif data.startswith("SIGNFULL"):
            pause_client = True
            packet_id = data.split(":", 1)[1].split(";", 1)
            print("Received SIGNFULL from server. Waiting for window to free up.")

        elif data.startswith("SIGNRDY"):
            pause_client = False
            packet_id = data.split(":", 1)[1].split(";", 1)
            print("Received SIGNRDY from server. Waiting for window to free up.")


def RUDP_Client(hostname):
    global connection_open
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind((client_ip,49152))
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print(f"Gonna try to connect to {resolved_ip}")
    print(" [RUDP] Sending a SIGNAL : SIGNEW to the RUDP Server")
    client.sendto(f"SIGNEW:{hostname}".encode(), (resolved_ip, 49152))

    sent_packets = {}
    packet_id = hostname_to_numeric(hostname)
    # Ajouter un thread pour écouter les messages entrants du serveur
    receive_thread = threading.Thread(target=receive, args=(client, sent_packets))
    receive_thread.start()

    while True:
        time.sleep(2)
        if pause_client == True :
            time.sleep(10)
        if not list_queue.empty():
            file_list = list_queue.get()
            download_file(file_list)
            break
        elif pause_client:
            for i in range(5):
                sys.stdout.write('.')
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write(
                '\b \b' * 3)  # Efface les trois points en revenant en arrière et en les remplaçant par des espaces
            sys.stdout.flush()

        elif not connection_open:
            create_new_connection = input(
                "Connection closed. Do you want to send SIGNEW to create a new connection? (yes/no): ")
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
            print("SIGNGET : to get the redirection to the server HTTP")
            print("SIGNEND : to end the connection")
            print("SIGNECHO : to know the ping with the server RUDP")
            print("SIGNSTAT : to know the stat of your connection with the server RUDP")
            print("-------------------------------------------------------")

            message = input("SIGNAL :")

            packet_id += 1

            if message == "SIGNGET":
                print(f" [RUDP] Sending a SIGNAL : n°{packet_id} SIGNGET to the RUDP Server")
                client.sendto(f"SIGNGET:{packet_id};{message}".encode(), (resolved_ip, 49152))
                sent_packets[packet_id] = message

            elif message == "SIGNEND":
                print(f" [RUDP] Sending a SIGNAL : n°{packet_id} SIGNEND to the RUDP Server")
                client.sendto(f"SIGNEND:{packet_id};{message}".encode(), (resolved_ip, 49152))
                sent_packets[packet_id] = message

            elif message == "SIGNECHO":
                timestamp = time.time()
                print(f" [RUDP] Sending a SIGNAL : n°{packet_id} SIGNECHO to the RUDP Server")
                client.sendto(f"SIGNECHO:{packet_id};{timestamp}".encode(), (resolved_ip, 49152))
                sent_packets[packet_id] = message

            elif message == "SIGNSTAT":
                print(f" [RUDP] Sending a SIGNAL : n°{packet_id} SIGNSTAT to the RUDP Server")
                client.sendto(f"SIGNSTAT:{packet_id}".encode(), (resolved_ip, 49152))
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

    #print("")

    # DNS Block
    #print(f"[DNS] Sending DNS request for the domain: {domain}")
    #dns_response = send_dns_query(dns_server_ip, domain, client_ip)
    #resolved_ip = extract_dns_response_ip(dns_response)
    #if resolved_ip:
    #    print(f"[DNS] The domain {domain} has been resolved to {resolved_ip}")
    #else:
    #    print(f"[DNS] The domain {domain} could not be resolved.")

    #print("")
    
    # RUDP Block
    RUDP_Client(hostname)

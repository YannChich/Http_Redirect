import socket
import time
import random
import threading

server_ip = "127.0.0.10"
packet_loss_rate = 0.10  # rate of loss 10%

def hostname_to_numeric(hostname):
    return sum(ord(c) for c in hostname)

def simulate_packet_loss(rate):
    return random.random() < rate

def send_with_loss(sock, message, addr, loss_rate):
    if not simulate_packet_loss(loss_rate):
        sock.sendto(message, addr)
    else:
        print(f"Simulated packet loss for message: {message}")

def handle_lost_packet(client, packet_id, sent_packets):
    packet_data = sent_packets.get(packet_id)
    print("-----------------------------------------------")
    print(f"Resending packet {packet_id}: {packet_data}")
    print("-----------------------------------------------")
    client.sendto(f"{packet_data}".encode(), (server_ip, 49152))

def receive(client, sent_packets):
    while True:
        data, addr = client.recvfrom(1024)
        data = data.decode()
        print(f"Received data: {data}")

        if data.startswith("SIGNLOST:"):
            print("Receive SIGNLOST, going to send the lost packet")
            packet_id = int(data.split(":", 1)[1])
            handle_lost_packet(client, packet_id, sent_packets)

        if data.startswith("SIGNACK"):
            print("Receive ACK from the RUDP Server.")
            
        elif data.startswith("ECHOREPLY:"):
            packet_id, timestamp = data.split(":", 1)[1].split(";", 1)
            latency = (time.time() - float(timestamp)) * 1000
            print(f"Received ECHOREPLY from server. Latency: {latency:.2f} ms")

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_name = input("Enter a name:")
    client_socket.sendto(f"SIGNEW:{client_name}".encode(), (server_ip, 49152))

    packet_id = hostname_to_numeric(client_name)
    sent_packets = {}

    receive_thread = threading.Thread(target=receive, args=(client_socket, sent_packets))
    receive_thread.start()

    while True:
        time.sleep(3)
        message = f"SIGNECHO:{packet_id};{time.time()}"
        print(f" [RUDP] Sending a SIGNAL : n°{packet_id} SIGNECHO to the RUDP Server")
        send_with_loss(client_socket, message.encode(), (server_ip, 49152), packet_loss_rate)
        sent_packets[packet_id] = message
        packet_id += 1

if __name__ == "__main__":
    main()
import socket
import time

SizeOfPacket = 1024
clients = []
Server_IP = "127.0.0.104"
Scrap_IP = "127.0.0.34"
max_window = 64
last_received_id = {}
unacked_packets = {}
client_info = {}


# Get files trough TCP connection
def get_files():
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((Server_IP, 49153))
    # Connect to the Scrap server
    client_socket.connect((Scrap_IP, 49153))  # Utilisez Scrap_IP ici
    print('Connected to Scrap server and asking for the list.')

    # Sending a signal to the scrap server
    message = "SIGNGET"
    client_socket.send(message.encode())

    # Receive data from the Scrap server
    data = client_socket.recv(1024).decode()
    print("Received the list of files.")

    # Close the connection
    client_socket.close()
    return data


def hostname_to_numeric(hostname):
    return sum(ord(c) for c in hostname)


def send_ack(server, addr, packet_id):
    server.sendto("SIGNACK".encode(), addr)
    client_info[addr]['congestion_window'] -= 1
    if addr in unacked_packets and packet_id in unacked_packets[addr]:
        del unacked_packets[addr][packet_id]


def send_lost_packet_signal(server, addr, expected_id):
    print(f"Sending SIGNLOST:{expected_id} to {addr}")
    server.sendto(f"SIGNLOST:{expected_id}".encode(), addr)


def send_signfull_signal(server, addr):
    print(f"Sending SIGNFULL to {addr}")
    server.sendto("SIGNFULL".encode(), addr)


def server_statistics(addr):
    info = client_info.get(addr)
    if not info:
        return "No client information available."

    elapsed_time = time.time() - info['connection_time']
    stats = f"Packets sent: {info['packets_sent']}\nPackets lost: {info['packets_lost']}\nConnected time: {elapsed_time:.2f} seconds"
    return stats


def remove_client(addr):
    global clients
    clients = [client for client in clients if client[1] != addr]


def receive(server):
    global last_received_id
    while True:
        try:
            data, addr = server.recvfrom(SizeOfPacket)
            data = data.decode()
            if data.startswith("SIGNEW:"):
                name = data[data.index(":") + 1:]
                numeric_value = hostname_to_numeric(name)
                clients.append((name, addr, numeric_value))
                last_received_id[addr] = numeric_value
                print(f"Client : {data} ")
                client_info[addr] = {'packets_sent': 0, 'packets_lost': 0, 'connection_time': time.time(),
                                     'congestion_window': 1}
                send_ack(server, addr, numeric_value)

            elif addr in client_info:
                congestion_window = client_info[addr]['congestion_window']
                if congestion_window < max_window:
                    client_info[addr]['congestion_window'] += 1
                else:
                    send_signfull_signal(server, addr)

                if data.startswith("SIGNGET:"):
                    packet_id, payload = data.split(":", 1)[1].split(";", 1)
                    packet_id = int(packet_id)
                    client_info[addr]['packets_sent'] += 1

                    if packet_id == last_received_id[addr] + 1:
                        print(f"Received SIGNGET {packet_id} from {addr}: {payload}")
                        last_received_id[addr] = packet_id
                        message = get_files()
                        time.sleep(0.5)
                        if addr in unacked_packets and packet_id in unacked_packets[addr]:
                            del unacked_packets[addr][packet_id]
                        client_info[addr]['congestion_window'] -= 1
                        server.sendto(f"ACKGET:{packet_id};{message}".encode(), addr)

                    else:
                        print(f"Received out of order packet {packet_id} from {addr}: {payload}")
                        client_info[addr]['packets_lost'] += 1
                        send_lost_packet_signal(server, addr, last_received_id[addr] + 1)

                elif data.startswith("SIGNECHO:"):
                    packet_id, timestamp = data.split(":", 1)[1].split(";", 1)
                    packet_id = int(packet_id)
                    last_received_id[addr] = packet_id
                    client_info[addr]['packets_sent'] += 1
                    print(f"Received SIGNECHO {packet_id} from {addr}. Sending back the timestamp.")
                    if addr in unacked_packets and packet_id in unacked_packets[addr]:
                        del unacked_packets[addr][packet_id]
                    client_info[addr]['congestion_window'] -= 1
                    server.sendto(f"ECHOREPLY:{packet_id};{timestamp}".encode(), addr)

                elif data.startswith("SIGNSTAT:"):
                    packet_id = int(data.split(":", 1)[1])
                    client_info[addr]['packets_sent'] += 1
                    last_received_id[addr] = packet_id
                    print(f"Received SIGNSTAT {packet_id} from {addr}. Sending server statistics.")
                    stats = server_statistics(addr)
                    if addr in unacked_packets and packet_id in unacked_packets[addr]:
                        del unacked_packets[addr][packet_id]
                    client_info[addr]['congestion_window'] -= 1
                    server.sendto(f"STATREPLY:{packet_id};{stats}".encode(), addr)

                elif data.startswith("SIGNEND:"):
                    packet_id, payload = data.split(":", 1)[1].split(";", 1)
                    packet_id = int(packet_id)
                    last_received_id[addr] = packet_id
                    print(f"Received SIGNEND {packet_id} from {addr}. Closing connection.")
                    send_ack(server, addr, packet_id)
                    remove_client(addr)
                    break

        except:
            pass


def main():
    print("RUDP Server Running")
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((Server_IP, 49152))

    receive(server)
    server.close()


if __name__ == "__main__":
    main()

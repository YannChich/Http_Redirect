import socket
import time

SizeOfPacket = 1024
clients = []
Server_IP = "127.0.0.40"
last_received_id = {}
unacked_packets = {}
client_info = {}


def hostname_to_numeric(hostname):
    return sum(ord(c) for c in hostname)


def send_ack(server, addr):
    server.sendto("SIGNACK".encode(), addr)


def send_lost_packet_signal(server, addr, expected_id):
    print(f"Sending SIGNLOST:{expected_id} to {addr}")
    server.sendto(f"SIGNLOST:{expected_id}".encode(), addr)


def send_signfull_signal(server, addr):
    print(f"Sending SIGNFULL to {addr}")
    server.sendto("SIGNFULL".encode(), addr)


def send_signrdy_signal(server, addr):
    print(f"Sending SIGNRDY to {addr}")
    server.sendto("SIGNRDY".encode(), addr)


def server_statistics(addr):
    info = client_info.get(addr)
    if not info:
        return "No client information available."

    elapsed_time = time.time() - info['connection_time']
    stats = f"Packets sent: {info['packets_sent']}\nPackets lost: {info['packets_lost']}\nConnected time: {elapsed_time:.2f} seconds"
    return stats


# Congestion Control
def congestion_control(server, addr):
    send_signfull_signal(server, addr)
    # The code for the congestion control
    send_signrdy_signal(server,addr)



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
                                     'congestion_window': 1, 'congestion_threshold': 64}
                send_ack(server, addr)

            elif data.startswith("SIGNGET:"):
                packet_id, payload = data.split(":", 1)[1].split(";", 1)
                packet_id = int(packet_id)
                client_info[addr]['packets_sent'] += 1


                if packet_id == last_received_id[addr] + 1:
                    print(f"Received packet {packet_id} GET from {addr}: {payload}")
                    last_received_id[addr] = packet_id
                else:
                    print(f"Received out of order packet {packet_id} from {addr}: {payload}")
                    client_info[addr]['packets_lost'] += 1
                    send_lost_packet_signal(server, addr, last_received_id[addr] + 1)

            elif data.startswith("SIGNECHO:"):
                packet_id, timestamp = data.split(":", 1)[1].split(";", 1)
                packet_id = int(packet_id)
                client_info[addr]['packets_sent'] += 1
                print(f"Received SIGNECHO from {addr}. Sending back the timestamp.")
                server.sendto(f"ECHOREPLY:{packet_id};{timestamp}".encode(), addr)

            elif data.startswith("SIGNSTAT:"):
                packet_id = int(data.split(":", 1)[1])
                client_info[addr]['packets_sent'] += 1
                print(f"Received SIGNSTAT from {addr}. Sending server statistics.")
                stats = server_statistics(addr)
                server.sendto(f"STATREPLY:{packet_id};{stats}".encode(), addr)

            elif data.startswith("SIGNEND:"):
                packet_id, payload = data.split(":", 1)[1].split(";", 1)
                packet_id = int(packet_id)
                last_received_id[addr] = packet_id
                print(f"Received SIGNEND from {addr}. Closing connection.")
                server.sendto(f"ACKEND:{packet_id}".encode(), addr)
                remove_client(addr)

        except:
            pass


def main():
    print("RUDP Server Running")
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((Server_IP, 49152))

    receive(server)


if __name__ == "__main__":
    main()
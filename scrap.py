import subprocess
import sys
import time
import requests
from bs4 import BeautifulSoup
import socket

Server_IP = "127.0.0.104"
Scrap_IP = "127.0.0.34"

def send_file_list(file_list):
    # Create TCP socket
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind((Scrap_IP, 49153))  # Utilisez Scrap_IP ici
    tcp_server.listen(1)
    print("Waiting for RUDP server to connect...")

    # Accept incoming connection
    conn, addr = tcp_server.accept()

    # Going to receive the message from rudp
    signal = conn.recv(1024).decode()

    if signal == "SIGNGET":
        # Send the file list to the RUDP server
        conn.sendall(file_list.encode())

        # Close the socket
        tcp_server.close()


# Find all the elements with the "p" tag and print their text
def list_maker():
    file_list = ""
    i = 1
    print("Which file would you like to download from: http://127.0.0.1/")
    for p in soup.find_all("a"):
        file_list += p.text + ";"
        i += 1
    print("[SCRAP] Sending file list to RUDP server.")
    send_file_list(file_list)

url = "http://127.0.0.1/"
response = requests.get(url)
html_content = response.content
soup = BeautifulSoup(html_content, "html.parser")

print("Looking for files available to download")
for i in range(2):
    sys.stdout.write('.')
    sys.stdout.flush()
    time.sleep(1)
sys.stdout.write('\b \b' * 3)
sys.stdout.flush()
list_maker()

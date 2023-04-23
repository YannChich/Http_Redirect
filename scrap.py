import subprocess
import sys
import time
import requests
from bs4 import BeautifulSoup

# Replace the URL below with the URL of the HTML page you want to scrape
url = "http://127.0.0.1/"

# Send a request to the URL and get the HTML content
response = requests.get(url)
html_content = response.content

# Use BeautifulSoup to parse the HTML content
soup = BeautifulSoup(html_content, "html.parser")
print("Looking for files available to download")
for i in range(2):
    sys.stdout.write('.')
    sys.stdout.flush()
    time.sleep(1)
sys.stdout.write('\b \b' * 3)
sys.stdout.flush()

# Find all the elements with the "p" tag and print their text
list = []
i = 1
print("Which file would you like to download from: http://127.0.0.1/")
for p in soup.find_all("a"):
    print(f"{i}: {p.text}")
    list.append(p.text)
    i += 1
while True:
    num = int(input("The number of the file you would like to download: "))
    if num <= len(list):
        filename = f"{list[num - 1]}"
        set_ip_command = f"wget http://127.0.0.1/{filename}"
        subprocess.run(set_ip_command, shell=True, check=True)
    else:
        print("Wrong file number.")

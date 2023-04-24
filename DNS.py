import socket

port = 53
ip = "127.0.0.7"
fixed_ip = "127.0.0.72"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))
print("DNS server Runing...")

def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    rflags = ''

    QR = '1'

    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(byte1) & (1 << bit))

    AA = '1'

    TC = '0'

    RD = '0'

    # Byte 2

    RA = '0'

    Z = '000'

    RCODE = '0000'

    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1,
                                                                                                             byteorder='big')

def getquestiondomain(data):
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y += 1

    questiontype = data[y:y + 2]

    return (domainparts, questiontype)

def buildquestion(domainname, rectype):
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

    for part in recval.split('.'):
        rbytes += bytes([int(part)])
    return rbytes

def buildresponse(data):
    # Transaction ID
    TransactionID = data[:2]

    # Get the flags
    Flags = getflags(data[2:4])

    # Question Count
    QDCOUNT = b'\x00\x01'

    # Answer Count
    ANCOUNT = (1).to_bytes(2, byteorder='big')

    # Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Additional Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # Create DNS body
    dnsbody = b''

    domain, questiontype = getquestiondomain(data[12:])

    dnsquestion = buildquestion(domain, 'a')

    dnsbody += rectobytes(domain, 'a', 60, fixed_ip)

    return dnsheader + dnsquestion + dnsbody

def log_request(data, addr):
    domain, questiontype = getquestiondomain(data[12:])
    print(f"Received DNS request from {addr[0]}:{addr[1]} for domain {'.'.join(domain)} with type {questiontype.hex()}")

while 1:
    data, addr = sock.recvfrom(512)

    # Log the received DNS request
    log_request(data, addr)

    r = buildresponse(data)
    sock.sendto(r, addr)


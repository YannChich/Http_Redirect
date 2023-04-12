import glob
import json
import socket

port = 53  # port of DNS
ip = '127.0.0.1'  # IP of loopback machine

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # We are using ipv4 and UDP
sock.bind((ip, port))


def load_zone():
    zonefiles = glob.glob('zones/*.zone')
    jsonzone = {}
    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data['$origin']
            jsonzone[zonename] = data
    return jsonzone


zonedata = load_zone()


def getflags(flags):
    byte1 = bytes(flags[:1])  # the first byte is : QR + OPCODE + AA + TC + RD
    byte2 = bytes(flags[1:2])  # the second byte is : RA + Z + RCODE
    rflags = ''

    QR = '1'  # a one bit field that specifies whether this message is a query = 0 or a response = 1

    OPCODE = ''  # a four bit field that specifies kind of query in this message. This value is set by the originator
    # of a query and copied into the response
    for bit in range(1, 5):  # we're going to run in every bit of the OPCODE to extract the exact value
        OPCODE += str(ord(byte1) & (1 << bit))

    AA = '1'  # Authoritative Answer - this bit is valid in responses and specifies that the responding name server
    # is an authority for the domain name in question section

    TC = '0'  # TrunCation - specifies that this message was truncated due to length greater than that permitted (>512)

    RD = '0'  # Recursion Desired -

    RA = '0'  # Recursion Available -

    Z = '000'  # Reserved for future use. Must be zero in all queries and responses.

    RCODE = '0000'  # Response code - this 4 bit field is set as part of response. 0 = No error condition

    return int(QR + OPCODE + AA + TC + RD).to_bytes(1, byteorder='big') + int(RA + Z + RCODE).to_bytes(1,
                                                                                                       byteorder='big')


def getQuestionDomain(data):
    state = 0
    expectedlength = 0
    domainString = ''
    domainpart = []
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainString += chr(byte)
            x += 1
            if x == expectedlength:
                domainpart.append(domainString)
                domainString = ''
                state = 0
                x = 0
            if byte == 0:
                domainpart.append(domainString)
                break

        else:
            state = 1
            expectedlength = byte
        y += 1

    questionType = data[y:y + 2]

    return (domainpart, questionType)


def getzone(domain):
    global zonedata

    zone_name = '.'.join(domain)
    return zonedata[zone_name]


def getrecs(data):
    domain, questionType = getQuestionDomain(data)
    qt = ''
    if questionType == b'\x00\x01':
        qt = 'a'  # Type A = 1

    zone = getzone(domain)

    return (zone[qt], qt, domain)


def buildquestion(domainname, rectype):
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes = ord(char).to_bytes(1, byteorder='big')

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
        rbytes = rbytes + bytes([0]) + bytes([1])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])

    return rbytes


def buildresponse(data):
    #   ------------------------------------------ Transaction ID --------------------------------------------
    TransactionID = data[0:2]  # Taking 2 bits of the Transaction ID of DNS , print(TransactionID) = ASCII convert

    #   ---------------------------------------------Get the flags-------------------------------------------
    Flags = getflags(data[2:4])

    # --------------------------------------------- Question Count ------------------------------------------
    QDCOUNT = b'\x00\x01'  # 2 bytes : the first 0 and the second = 1

    # ---------------------------------------------- Answer Count ---------------------------------------------

    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    # ----------------------------------------------- Nameserver Count ----------------------------------------
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # ----------------------------------------------- Additional Count ----------------------------------------
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    DNS_Header = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    DNS_Body = b''

    # ------------------------------------------ Get answer for query ------------------------------------------
    records, rectype, domainname = getrecs(data[12:])

    DNS_Question = buildquestion(domainname, rectype)

    for record in records:
        DNS_Body += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return DNS_Header + DNS_Question + DNS_Body


while 1:
    data, addr = sock.recvfrom(512)
    resp = buildresponse(data)
    sock.sendto(resp, addr)

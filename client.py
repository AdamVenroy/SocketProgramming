"""Client file"""

import sys
import socket
from server_and_client_functions import *


def create_dt_request(request_type):
    """Return byte """
    packet = bytearray(6)
    packet[0] = 0x49
    packet[1] = 0x7E
    packet[2] = 0x00
    packet[3] = 0x01
    packet[4] = 0x00
    if request_type == "date":
        packet[5] = 0x01
    elif request_type == "time":
        packet[5] = 0x02
    return packet

def main():
    args = sys.argv[1:]

    if len(args) != 3:
        print_error("Please enter three arguments - (request_type, address, port).", True)
    if args[0] != "date" and args[0] != "time":
        print_error('Please enter string "date" or "time" as first argument', True)

    try:
        port = int(args[2])
    except ValueError:
        print_error("Please enter an integer for port", True)

    check_port(port)

    try:
        address = socket.getaddrinfo(args[1], port)[-1][-1]
    except:
        print_error("getaddrinfo failed. Did you enter a valid address?", True)

    packet = create_dt_request(args[0])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.settimeout(1)
    print(f"Sending packet to {address}")

    try:
        server_socket.connect(address)
        server_socket.sendto(packet, address)
    except Exception as e:
        print("Failed to packet to address")
        print_error(e, True)

    print("Packet sent successfully")
    print("Waiting for response packet...")

    try:
        packet = server_socket.recvfrom(1024)[0]
    except TimeoutError:
        print_error("Timeout. Is a server running at the address and port? Is there a serverside error?", True)
    except OSError as oserror:
        print(oserror)
        print_error("OSError. Did the packet length exceed the buffer?  Is a server running at the address and port?", True)

    print(f"Packet received from {address}")
    check_dt_response_packet(packet, should_exit=True, print_data=True)
    server_socket.close()



if __name__ == '__main__':
    main()

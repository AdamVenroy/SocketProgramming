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
    
def check_dt_response_packet(data, should_exit=False, print_data=False):
    """Checks that DT-Response Packet is valid. If print_data is true, 
    it will print the packet info"""
    if len(data) < 13:
        print_error("Data smaller than 13 bytes", should_exit)
        return False
    magic_number = (data[0] << 8) + data[1]
    packet_type = (data[2] << 8) + data[3]
    language_code = (data[4] << 8) + data[5]
    year = (data[6] << 8) + data[7]
    month = data[8]
    day = data[9]
    hour = data[10]
    minute = data[11]
    length = data[12]
    text = data[13:].decode("utf-8")
    print("Checking DT-Response packet...")
    if magic_number != 0x497E:
        print_error(f"Magic number does not equal 0x497E and "+
        "instead equals {hex(magic_number)}", should_exit)
        return False
    if packet_type != 0x0002:
        print_error(f"Packet Type does not equal 0x0002 and "+
        "instead equals {hex(packet_type)}", should_exit)
        return False
    if not(1 <= language_code <= 3):
        print_error(f"Language code does not equal 0x001, 0x002 or 0x003 and "+
         "instead equals {hex(language_code)}", should_exit)
        return False
    if year >= 2100:
        print_error(f"Year is not below 2100 as year equals {year}", 
        should_exit)
        return False
    if not(1 <= month <= 12):
        print_error(f"Month is not between 1 and 12 as month equals {month}", 
        should_exit)
        return False
    if not(1 <= day <= 31):
        print_error(f"Day is not between 1 and 31 as day equals {day}", 
        should_exit)
        return False
    if not(0 <= hour <= 23):
        print_error(f"Hour is not between 0 and 23 as hour equals {hour}", 
        should_exit)
        return False
    if not(0 <= minute <= 59):
        print_error(f"Minute is not between 0 and 59 as minute equals {minute}", 
        should_exit)
        return False
    if not(len(data) == 13 + length):
        print_error(f"Invalid length, packet length = {len(data)}, "+
        "length in header + header length = {length + 13}", should_exit)
        return False
    print("Checks passed")
    
    if print_data:
        print(f"Magic Number: {hex(magic_number)}")
        print(f"Packet Type: {packet_type}")
        print(f"Language Code: {language_code}")
        print(f"Year: {year}")
        print(f"Month: {month}")
        print(f"Day: {day}")
        print(f"Hour: {hour}")
        print(f"Minute: {minute}")
        print(f"Length: {length}")
        print(f'Text: "{text}"')
    
    return True

def main():
    args = sys.argv[1:]

    if len(args) != 3:
        print_error("Please enter three arguments - "+
        "(request_type, address, port).", True)
    if args[0] != "date" and args[0] != "time":
        print_error('Please enter string "date" or "time" as first argument', 
        True)

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
        packet = server_socket.recvfrom(70)[0]
    except TimeoutError:
        print_error("Timeout. Is a server running at the address and port? "+
        "Is there a serverside error?", True)
    except OSError as oserror:
        print(oserror)
        print_error("OSError. Was the packet too big for the buffer?", True)

    print(f"Packet received from {address}")
    check_dt_response_packet(packet, should_exit=True, print_data=True)
    server_socket.close()


if __name__ == '__main__':
    main()

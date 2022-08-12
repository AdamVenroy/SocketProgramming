"""Server file"""

import sys
import socket
import datetime
import select
from server_and_client_functions import *

# month : (english, maori, german)
MONTHS = {
    1 : ("January", "Kohitātea", "Januar"),
    2 : ("February","Hui-tanguru","Februar"),
    3 :  ("March","Poutū-te-rangi","Mârz"),
    4 : ("April","Paenga-whāwhā","April"),
    5 : ("May","Haratua","Mai"),
    6 : ("June","Pipiri","Juni"),
    7 : ("July","Hōngongo","Juli"),
    8 : ("August","Here-turi-kōkā","August"),
    9 : ("September","Mahuru","September"),
    10 : ("October","Whiringa-ā-nuku","Oktober"),
    11 : ("November","Whiringa-ā-rangi","November"),
    12 : ("December","Hakihea","Dezember")
}


def check_arguments_and_return_port_list(arguments):
    """ Checks if the arguments given are valid port numbers. If they are, returns a list of ports.
    Otherwise prints an error and exits.
    """
    if len(arguments) != 3:
        print_error("Error: Please enter three ports.", True)

    try:
        ports = [int(i) for i in arguments]
    except ValueError:
        print_error("Error: Please enter integers between 1024 and 64000 for ports", True)

    if len(ports) != len(set(ports)):
        print_error("Error: Please enter three unique values for the ports", True)

    for p in ports:
        check_port(p)


    return ports


def create_dt_reponse(language_code, request_type):
    """Creates a DT-Response packet. Text is determined on the language_code and request_type"""
    today = datetime.datetime.today()
    year = today.year
    month = today.month
    day = today.day
    hour = int(today.strftime("%H"))
    minute = int(today.strftime("%M"))
    if request_type == 1:
        text = date_text(language_code, day, month, year)
    if request_type == 2:
        text = time_text(language_code, hour, minute)
    
    text = text.encode('utf-8')
    if len(text) > 255:
        print_error("Text message too long")

    length = len(text)

    header = bytearray(13)
    header[0] = 0x49
    header[1] = 0x7E
    header[2] = 0x00
    header[3] = 0x02
    header[4] = 0x00
    header[5] = language_code
    header[6] = (year & 0xFF00) >> 8
    header[7] = year & 0xFF
    header[8] = month
    header[9] = day
    header[10] = hour
    header[11] = minute
    header[12] = length
    packet = header + text
    
    return packet


def time_text(language_code, hour, minute):
    if language_code == 1:
        return f"The current time is {hour:02d}:{minute:02d}"
    if language_code == 2:
        return f"Ko te wa o tenei wa {hour:02d}:{minute:02d}"
    if language_code == 3:
        return f"Die Uhrzeit ist {hour:02d}:{minute:02d}"


def date_text(language_code, day, month, year):
    month_text = MONTHS[month][language_code-1]
    if language_code == 1:
        return f"Today’s date is {month_text} {day}, {year}"
    if language_code == 2:
        return f"Ko te ra o tenei ra ko {month_text} {day}, {year}"
    if language_code == 3:
        return f"Heute ist der {day}. {month_text} {year}"


def create_and_bind_socket(port):
    """ Returns UDP IPv4 Server Socket binded on port given"""
    try:
        hostname = socket.getfqdn()
    except Exception as e:
        print(e)
        print_error("Unable to get hostname", True)
    print(f"Running on host {hostname}")
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((hostname,port))
    except Exception as e:
        print(e)
        print_error(f"Unable to bind to port {port}", should_exit=True)
    return server_socket



def main():
    arguments = sys.argv[1:]
    ports = check_arguments_and_return_port_list(arguments)
    list_of_sockets = [create_and_bind_socket(p) for p in ports]
    print(f"Sockets successfully created and binded on address on ports {ports[0]}, {ports[1]} and {ports[2]}.")
    while True:
        print("Waiting for packet(s)...")
        rlist, _, _ = select.select(list_of_sockets, [], [])
        print("Packet(s) received")
        for s in rlist:
            try:
                packet, address = s.recvfrom(48)
            except OSError as error:
                print(error)
                print_error("OS Error. Did packet length exceed buffer of 48 bits?", False)
            else:
                port = s.getsockname()[1]
                print(f"Request received from {address} on port {port}")
                if check_dt_request_packet(packet):
                    language_code = ports.index(port) + 1
                    request_type = (packet[4] << 8) + packet[5]
                    response_packet = create_dt_reponse(language_code, request_type)
                    print(f"Sending DT-Response packet to {address}")
                    try:
                        s.sendto(response_packet, address)
                    except Exception as e:
                        print(e)
                        print_error(f"Sending DT-Response to {address}")











            
        


if __name__ == '__main__':
    main()

"""Functions that both the server and client need"""

def check_port(p):
    """Exits program if p is not between 1024 and 6400-"""
    if not(1024 <= p <= 64000):
        print_error("Error: Please enter integers between 1024 and 64000 for ports", True)

def print_error(message, should_exit):
    """ Prints error messages and then exits the program"""
    print(f"Error: {message}")
    if should_exit:
        exit()

def check_dt_request_packet(data, should_exit=False, print_data=False):
    """Checks DT-Request packet is valid. If print_data is true, it will print the packet info. 
    If exit is true, the program will exit upon detecting an error. 
    """
    if len(data) != 6:
        print_error("Data is not 6 bytes", should_exit)
        return False
    magic_number = (data[0] << 8) + data[1]
    packet_type = (data[2] << 8) + data[3]
    request_type = (data[4] << 8) + data[5]
    print("Checking DT-Request packet...")
    if magic_number != 0x497E:
        print_error(f"Magic number does not equal 0x497E and instead equals {hex(magic_number)}", should_exit)
        return False
    if packet_type != 0x0001:
        print_error(f"Packet Type does not equal 0x0002 and instead equals {hex(packet_type)}", should_exit)
        return False
    if request_type != 1 and request_type != 2:
        print_error(f"Request Type does not equal 0x0001 or 0x0002 and instead equals {hex(request_type)}", should_exit)
        return False
    
    print("Checks passed")

    if print_data:
        print(f"Magic Number: {hex(magic_number)}")
        print(f"Packet Type: {packet_type}")
        print(f"Request Type: {request_type}")

    return True


def check_dt_response_packet(data, should_exit=False, print_data=False):
    """Checks that DT-Response Packet is valid. If print_data is true, it will print the packet info"""
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
        print_error(f"Magic number does not equal 0x497E and instead equals {hex(magic_number)}", should_exit)
        return False
    if packet_type != 0x0002:
        print_error(f"Packet Type does not equal 0x0002 and instead equals {hex(packet_type)}", should_exit)
        return False
    if not(1 <= language_code <= 3):
        print_error(f"Language code does not equal 0x001, 0x002 or 0x003 and instead equals {hex(language_code)}", should_exit)
        return False
    if year >= 2100:
        print_error(f"Year is not below 2100 as year equals {year}", should_exit)
        return False
    if not(1 <= month <= 12):
        print_error(f"Month is not between 1 and 12 as month equals {month}", should_exit)
        return False
    if not(1 <= day <= 31):
        print_error(f"Day is not between 1 and 31 as day equals {day}", should_exit)
        return False
    if not(0 <= hour <= 23):
        print_error(f"Hour is not between 0 and 23 as hour equals {hour}", should_exit)
        return False
    if not(0 <= minute <= 59):
        print_error(f"Minute is not between 0 and 59 as minute equals {minute}", should_exit)
        return False
    if not(len(data) == 13 + length):
        print_error(f"Invalid length, packet length = {len(data)}, length in header + header length = {length + 13}", should_exit)
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
"""Functions and constants that both the server and client need"""
ZERO_BYTE = 0x00
MAGIC_NUMBER = 0x497E
MAGIC_NUMBER_NIBBLE_1 = 0x49
MAGIC_NUMBER_NIBBLE_2 = 0x7E
REQUEST_PACKET_TYPE = 0x01
DATE_REQUEST = 0x01
TIME_REQUEST = 0x02
RESPONSE_PACKET_TYPE = 0x02


def check_port(p):
    """Exits program if p is not between 1024 and 6400-"""
    if not(1024 <= p <= 64000):
        print_error("Error: Please enter integers between " 
        +"1024 and 64000 for ports", True)

def print_error(message, should_exit):
    """ Prints error messages and then exits the program"""
    print(f"Error: {message}")
    if should_exit:
        exit()



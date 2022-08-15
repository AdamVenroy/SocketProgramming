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



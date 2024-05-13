import socket

def connect_to_node(host, port=8333):
    """Creates a TCP socket connecting to the host specified and the Bitcoin port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


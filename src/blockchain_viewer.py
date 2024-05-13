import socket
import time
import random
import struct
import hashlib
import binascii


# Binary encode the sub-version
# Source: https://dev.to/alecbuda/introduction-to-the-bitcoin-network-protocol-using-python-and-tcp-sockets-1le6    
def create_sub_version():
    sub_version = "/Satoshi:0.7.2/"
    return b'\x0F' + sub_version.encode()


# Create the TCP request object
# Source: https://dev.to/alecbuda/introduction-to-the-bitcoin-network-protocol-using-python-and-tcp-sockets-1le6    
def create_message(magic, command, payload):
    """Creates a TCP request object with the specified magic number, command, and payload."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    return(struct.pack('L12sL4s', magic, command.encode(), len(payload), checksum) + payload)


# Create the "version" request payload
def create_payload_version():
    version = struct.pack('i', 70015)  # Protocol version 70015
    services = struct.pack('Q', 0)  # Node services (0 for none)
    timestamp = struct.pack('q', int(time.time()))

    # Network address 
    addr_recv = struct.pack('>Q16s', 0, b'\x00'*16)
    addr_from = struct.pack('>Q16s', 0, b'\x00'*16) # This is ignored in version messages so it's filled with dummy values
    
    nonce = struct.pack('Q',random.getrandbits(64))
    user_agent_bytes = b'/Satoshi:0.7.2/'  # User agent
    user_agent = struct.pack('B', len(user_agent_bytes)) + user_agent_bytes
    start_height = struct.pack('i', -1)
    relay = struct.pack('?', False)
    payload = version + services + timestamp + addr_recv + addr_from + nonce + user_agent + start_height + relay

    return(payload)

print(create_payload_version())


def connect_to_node(host, port=8333):
    """Creates a TCP socket connecting to the host specified and the Bitcoin port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


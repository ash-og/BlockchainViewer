import socket
import time
import random
import struct
import hashlib
import binascii


# Create the TCP request object
# Source: https://dev.to/alecbuda/introduction-to-the-bitcoin-network-protocol-using-python-and-tcp-sockets-1le6    
def create_message(command, payload):
    """Creates a TCP request object with the magic number, command, and payload."""
    magic = 0xd9b4bef9  # Magic number for the main network
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

#print(create_payload_version())

# Create the "verack" request message
# Source: https://dev.to/alecbuda/introduction-to-the-bitcoin-network-protocol-using-python-and-tcp-sockets-1le6    
def create_message_verack():
    return bytearray.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")


#Get Data Request

# Print response
def print_response(command, request_data, response_data):
    print("")
    print("Command: " + command)
    print("Request:")
    print(binascii.hexlify(request_data))
    print("Response:")
    print(binascii.hexlify(response_data))

#Parsers


# get Data Request


if __name__ == '__main__':
    # Set constants
    peer_ip_address = '188.165.244.143'
    peer_tcp_port = 8333
    buffer_size = 1024

    # Create Request Objects
    version_payload = create_payload_version()
    print("Version Payload: ", version_payload)
    version_message = create_message('version', version_payload)
    verack_message = create_message_verack()
    # getdata_payload = create_payload_getdata(tx_id)
    # getdata_message = create_message(magic_value, 'getdata', getdata_payload)

    # Establish TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip_address, peer_tcp_port))

    # Send message "version"
    s.send(version_message)
    response_data = s.recv(buffer_size)
    print_response("version", version_message, response_data)

    # Send message "verack"
    s.send(verack_message)
    response_data = s.recv(buffer_size)
    print_response("verack", verack_message, response_data)

    # Send message "getdata"
    # s.send(getdata_message)
    # response_data = s.recv(buffer_size)
    # print_response("getdata", getdata_message, response_data)

    # Close the TCP connection
    s.close()
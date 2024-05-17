import socket
import time
import random
import struct
import hashlib
import binascii


# Create the TCP request object
def create_message(command, payload):
    """Creates a TCP request object with the magic number, command, and payload."""
    magic = 0xd9b4bef9  # Magic number for the main network
    command = command.encode() + b'\x00' * (12 - len(command))  # pad command to 12 bytes
    payload_size = len(payload)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    header = struct.pack('<L12sL4s', magic, command, payload_size, checksum)
    return header + payload


# Create the "version" request payload
def create_payload_version():
    version = struct.pack('<i', 70015)  # Protocol version 70015
    services = struct.pack('<Q', 0)    # Node services (0 for none)
    timestamp = struct.pack('<q', int(time.time()))
    addr_recv = b"\x00" * 26  # Dummy addresses and ports
    addr_from = b"\x00" * 26
    nonce = struct.pack('<Q',random.getrandbits(64))
    user_agent_bytes = b'/Satoshi:0.7.2/'  # User agent
    user_agent = struct.pack('<B', len(user_agent_bytes)) + user_agent_bytes
    start_height = struct.pack('<i', -1) # start height unknown (-1)
    relay = struct.pack('<?', False)
    return version + services + timestamp + addr_recv + addr_from + nonce + user_agent + start_height + relay


#print(create_payload_version())

#Get Data Request


#Parsers



if __name__ == '__main__':
    # Set constants
    peer_ip_address = '167.172.139.248'
    peer_tcp_port = 8333

    # Establish TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip_address, 8333))

    # Create Request Objects
    version_payload = create_payload_version()
    version_message = create_message('version', version_payload)

    # Send message 'version'
    s.send(version_message)
    response_data = s.recv(1024)
    print("Received response:", response_data)
    if response_data:
        # NOTE: check for magic number?
        # Getting command type to check if it's 'version'
        command = response_data[4:16].strip(b'\x00').decode('utf-8')
        if command == 'version':
            print("Received 'version' message")
            # Send 'verack' after receiving 'version'
            verack_msg = create_message('verack', b'')
            s.send(verack_msg)
            print("Sent 'verack' message")
            # Receive 'verack' message
            s.recv(1024)
            print("Received 'verack' message")

    print("Here")
    try:
        # Continuously listen for messages
        while True:
            msg = s.recv(2048) 
            if not msg:
                break
            print("Received message:", msg)
    except Exception as e:
        print("Error:", e)
    finally:
        s.close()

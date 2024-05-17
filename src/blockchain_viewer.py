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
def get_data_request(inv_list):
    count = len(inv_list)
    inv_payload = encode_varint(count)  # Encode count as varint
    for inv_item in inv_list:
        inv_type, inv_hash = inv_item
        inv_payload += struct.pack('<I', inv_type) + inv_hash
    return create_message('getdata', inv_payload)


#Parsers
def read_varint(payload):
    value = payload[0]
    if value < 253:
        return value, 1
    elif value == 253:
        return struct.unpack('<H', payload[1:3])[0], 3
    elif value == 254:
        return struct.unpack('<I', payload[1:5])[0], 5
    else:
        return struct.unpack('<Q', payload[1:9])[0], 9
    
def encode_varint(value):
    if value < 0xfd:
        return struct.pack('<B', value)
    elif value <= 0xffff:
        return struct.pack('<B', 0xfd) + struct.pack('<H', value)
    elif value <= 0xffffffff:
        return struct.pack('<B', 0xfe) + struct.pack('<I', value)
    else:
        return struct.pack('<B', 0xff) + struct.pack('<Q', value)

def parse_magic(message):
    return binascii.hexlify(message[:4]).decode('utf-8')
                                        
def handle_message(message):
    command = message[4:16].strip(b'\x00').decode('utf-8')
    length = struct.unpack('<I', message[16:20])[0]
    checksum = struct.unpack('<I', message[20:24])[0]
    payload = message[24:24+length]
    return command, length, checksum, payload

def parse_inv_payload(payload):
    count, offset = read_varint(payload)
    inv_list = []
    for _ in range(count):
        inv_type = struct.unpack('<I', payload[offset:offset+4])[0]
        inv_hash = payload[offset+4:offset+36]
        inv_list.append((inv_type, inv_hash))
        offset += 36
    return inv_list



def parse_block(payload):
    version = payload[:4]
    prev_block = payload[4:36]
    merkle_root = payload[36:68]
    timestamp = payload[68:72]
    bits = payload[72:76]
    nonce = payload[76:80]
    return version, prev_block, merkle_root, timestamp, bits, nonce


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
    if response_data:
        # Getting command type to check if it's 'version'
        command = response_data[4:16].strip(b'\x00').decode('utf-8')
        if command == 'version':
            print("Received 'version' message")
            # Send 'verack' after receiving 'version'
            verack_msg = create_message('verack', b'')
            s.send(verack_msg)
            print("Sent 'verack' message")
            # Receive 'verack' message
            verack_response = s.recv(1024)
            command = verack_response[4:16].strip(b'\x00').decode('utf-8')
            if command == 'verack':
                print("Received 'verack' message")

    print("Connected to bitcoin network!")
    try:
        # Continuously listen for messages
        buffer = b""
        while True:
            buffer += s.recv(2048)
            while len(buffer) >= 24:  # Waiting for the buffer to reach minimum length of a Bitcoin message header
                # Extract magic number and check if it's correct
                magic = parse_magic(buffer)
                if magic != 'f9beb4d9':
                    print("Magic:", magic)
                    # Skip the first byte and reattempt parsing
                    buffer = buffer[1:]
                    continue

                command, length, checksum, payload = handle_message(buffer)
                total_length = 24 + length
                if len(buffer) < total_length:
                    break  # Wait for the complete message

                message = buffer[:total_length]
                buffer = buffer[total_length:]

                if command == 'inv':
                    inv_list = parse_inv_payload(payload)
                    print("Received 'inv' message with", len(inv_list), "inventory items")
                    get_data_msg = get_data_request(inv_list)
                    s.send(get_data_msg)

                elif command == 'block':
                    print("Received 'block' message")
                    version, prev_block, merkle_root, timestamp, bits, nonce = parse_block(payload)
                    print("Block Version:", version)
                    print("Previous Block Hash:", binascii.hexlify(prev_block).decode('utf-8'))
                    print("Merkle Root:", binascii.hexlify(merkle_root).decode('utf-8'))
                    print("Timestamp:", struct.unpack('<I', timestamp)[0])
                    print("Bits:", struct.unpack('<I', bits)[0])
                    print("Nonce:", struct.unpack('<I', nonce)[0])

                elif command == 'tx':
                    print("Received 'tx' message")

                elif command == 'ping':
                    print("Received 'ping' message")
                    pong_msg = create_message('pong', payload)
                    s.send(pong_msg)

                else:
                    print("Received", command, "message")

    except Exception as e:
        print("Error:", e)
        print("Closing connection...")
    finally:
        s.close()
import socket
import time
import random
import struct
import hashlib
import binascii
from datetime import datetime

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

# Get Data Request
def get_data_request(inv_list):
    count = len(inv_list)
    inv_payload = encode_varint(count)  # Encode count as varint
    for inv_item in inv_list:
        inv_type, inv_hash = inv_item
        inv_payload += struct.pack('<I', inv_type) + inv_hash
    return create_message('getdata', inv_payload)

# Parsers
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

def handle_message(buffer):
    if len(buffer) < 24:
        return None, buffer  # Incomplete message header

    command = buffer[4:16].strip(b'\x00').decode('utf-8')
    length = struct.unpack('<I', buffer[16:20])[0]
    checksum = struct.unpack('<I', buffer[20:24])[0]

    total_length = 24 + length
    if len(buffer) < total_length:
        return None, buffer  # Incomplete message

    payload = buffer[24:24+length]
    message = (command, length, checksum, payload)
    buffer = buffer[total_length:]

    return message, buffer

def parse_inv_payload(payload):
    count, offset = read_varint(payload)
    inv_list = []
    for _ in range(count):
        inv_type = struct.unpack('<I', payload[offset:offset+4])[0]
        inv_hash = payload[offset+4:offset+36]
        inv_list.append((inv_type, inv_hash))
        offset += 36
    return inv_list

def parse_tx_outputs(payload, offset):
    output_count, varint_size = read_varint(payload[offset:])
    offset += varint_size
    outputs = []

    for i in range(output_count):
        value = struct.unpack('<Q', payload[offset:offset + 8])[0]
        offset += 8
        script_length, varint_size = read_varint(payload[offset:])
        offset += varint_size
        script = payload[offset:offset + script_length]
        offset += script_length
        outputs.append((value, script))
    
    return outputs, offset

def parse_tx(payload, offset):
    start_offset = offset
    version = struct.unpack('<I', payload[offset:offset + 4])[0]
    offset += 4

    input_count, varint_size = read_varint(payload[offset:])
    offset += varint_size

    # Skipping the inputs parsing as I won't be using it
    for _ in range(input_count):
        offset += 36  # Previous output (32-byte hash + 4-byte index)
        script_length, varint_size = read_varint(payload[offset:])
        offset += varint_size + script_length + 4  # Script length + script + sequence

    # Parse outputs
    outputs, offset = parse_tx_outputs(payload, offset)

    lock_time = struct.unpack('<I', payload[offset:offset + 4])[0]
    offset += 4

    return version, outputs, lock_time, offset - start_offset

def parse_block(payload):
    version = struct.unpack('<I', payload[0:4])[0]
    prev_block = payload[4:36]
    merkle_root = payload[36:68]
    timestamp = struct.unpack('<I', payload[68:72])[0]
    bits = struct.unpack('<I', payload[72:76])[0]
    nonce = struct.unpack('<I', payload[76:80])[0]

    # Parse transactions
    offset = 80
    tx_count, varint_size = read_varint(payload[offset:])
    offset += varint_size

    transactions = []
    for _ in range(tx_count):
        if offset >= len(payload):
            print("Error: Reached end of payload while parsing transactions")
            break
        tx_version, tx_outputs, tx_lock_time, tx_length = parse_tx(payload, offset)
        transactions.append((tx_version, tx_outputs, tx_lock_time))
        offset += tx_length  # Update offset to new position

    return version, prev_block, merkle_root, timestamp, bits, nonce, transactions

# Helper functions

def format_output(output):
    value = output[0]
    script = binascii.hexlify(output[1]).decode('utf-8')
    return f"Output Value: {value} sats\nScript: {script}"

def verify_block_hash(block_header):
    return hashlib.sha256(hashlib.sha256(block_header).digest()).digest()

# Main

if __name__ == '__main__':
    # Set constants
    peer_ip_address = '167.172.139.248'
    peer_tcp_port = 8333

    # Establish TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)  # Set timeout for the socket
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
            print("Waiting for message...\n")
            try:
                data = s.recv(2048)
                if not data:
                    print("No data received, retrying...")
                    continue
                buffer += data
                print("Added to buffer, current length:", len(buffer))
            except socket.timeout:
                print("Socket timed out, retrying...")
                continue

            while len(buffer) >= 24:  # Waiting for the buffer to reach minimum length of a Bitcoin message header
                print("Reached header length\n")
                # Extract magic number and check if it's correct
                magic = parse_magic(buffer)
                if magic != 'f9beb4d9':
                    print("Magic:", magic)
                    # Skip the first byte and reattempt parsing
                    buffer = buffer[1:]
                    continue

                message, buffer = handle_message(buffer)
                if message is None:
                    print("Incomplete message received, waiting for more data")
                    break  # Wait for the complete message

                command, length, checksum, payload = message
                print("Buffer Length after processing message:", len(buffer))

                if command == 'inv':
                    inv_list = parse_inv_payload(payload)
                    print("Received 'inv' message with", len(inv_list), "inventory items")
                    get_data_msg = get_data_request(inv_list)
                    s.send(get_data_msg)

                elif command == 'block':
                    print("Received 'block' message")
                    try:
                        version, prev_block, merkle_root, timestamp, bits, nonce, transactions = parse_block(payload)
                        
                        print("Block Version:", version)
                        print("Previous Block Hash:", binascii.hexlify(prev_block).decode('utf-8'))
                        print("Merkle Root:", binascii.hexlify(merkle_root).decode('utf-8'))
                        
                        # Convert timestamp to human-readable format
                        block_time = datetime.fromtimestamp(timestamp).strftime('%d %B %Y at %H:%M')
                        print("Block Timestamp:", block_time)
                        
                        print("Difficulty Bits:", bits)
                        print("Nonce:", nonce)

                        print("Transactions:")
                        for tx_index, (tx_version, tx_outputs, tx_lock_time) in enumerate(transactions):
                            print(f"  Transaction {tx_index + 1} (Version: {tx_version}, Lock Time: {tx_lock_time})")
                            for output_index, output in enumerate(tx_outputs):
                                print(f"    Output {output_index + 1}")
                                print(format_output(output))

                        # Verify block hash
                        block_header = payload[:80]
                        calculated_hash = verify_block_hash(block_header)
                        print("Block Hash:", binascii.hexlify(calculated_hash).decode('utf-8'))
                    except IndexError as e:
                        print("Error while parsing block:", e)
                        break

                elif command == 'tx':
                    print("New Transaction")
                    # print("New Transaction")
                    # version, outputs = parse_tx(payload)
                    # print("--------------------------------------")
                    # print(f"Transaction Version: {version}")
                    # print("\n")

                    # for i, output in enumerate(outputs):
                    #     print(f"Output {i+1}")
                    #     print(format_output(output))    
                    #     print("\n")
                    # print("--------------------------------------")

                elif command == 'ping':
                    pong_msg = create_message('pong', payload)
                    s.send(pong_msg)
                    print("Sent 'pong' message")

                else:
                    print("Received", command, "message")

    except Exception as e:
        print("Error:", e)
        print("Closing connection...")
    finally:
        s.close()

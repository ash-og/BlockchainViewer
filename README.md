# Python Bitcoin Explorer 

This project is a simple Python implementation of a Bitcoin Explorer. It connects to the Bitcoin network and handles basic message types like version, inv, block, and tx.

## Requirements

    Python 3.11.5
    Required libraries: socket, time, random, struct, hashlib, binascii, datetime

## Installation

1. Clone the repo:  
```
git clone https://github.com/ash-og/BlockchainViewer
cd BlockchainViewer
```

2. Install the necessary libraries:
```
pip install -r requirements.txt
```

## Usage

To run the script, execute:

```
cd src
python3 blockchain_viewer.py
```

## Code Overview
### Functions

- **create_message(command, payload):**  
    Creates a TCP request object with given command, and payload.

- **create_payload_version():**  
    Creates a payload for the version message.

- **get_data_request(inv_list):**  
    Creates a getdata message for a list of inventory items.

- **read_varint(payload):**  
    Reads a variable integer from the payload.

- **encode_varint(value):**  
    Encodes a value as a variable integer.

- **parse_magic(message):**  
    Parses the magic number from the message.

- **handle_message(buffer):**  
    Parses and handles different messages.

- **parse_inv_payload(payload):**  
    Parses the inventory payload.

- **parse_tx_outputs(payload, offset):**  
    Parses the transaction outputs.

- **parse_tx(payload, offset):**  
    Parses a transaction from the payload.

- **parse_block(payload):**  
    Parses a block from the payload.

- **format_output(output):**  
    Formats transaction output for printing.

- **verify_block_hash(block_header):**  
    Verifies the block hash.

- **connect_to_socket(peer_ip_address, peer_tcp_port):**  
    Connects to a peer node using the peer IP address and the given port.

- **handle_version_verack(s):**  
    Handles the exchange of version and verack messages.

Main Workflow

1. **Set Constants:**  
    Set the peer IP address and TCP port for the Bitcoin node.

2. **Establish TCP Connection:**  
    Connect to the Bitcoin node using connect_to_socket.

3. **Send / Receive Version and Verack:**  
    Send the version message and handle the verack response using handle_version_verack.

4. **Listen for Messages:**  
    Continuously listen for messages from the node, handling different message types:  
    - **inv:** Inventory message - requests data for the inventory items.
    - **block:** Block message - parses and prints block details.
    - **tx:** Transaction message - parses and prints transaction details.
    - **ping:** Responds with a pong message to keep the connection alive.
    - **Everything else:** Prints the command.
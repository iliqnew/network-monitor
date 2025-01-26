# network-monitor
Designed to keep track of a machine's network traffic and potentially provide the beginning of a pipeline of filters, alerts and processes.

Network Monitor is a project built entirely for the needs of cybersecurity and basic education in networking, development and automatization.

Feel free to tweak around with the packets and propose updates.


## Features
- Captures network traffic in real-time
- Filters packets based on source and destination IP addresses
- Displays packets in a text area
- Saves packets to a JSON file

## Usage
1. Run the program
2. Enter the IP address of the machine you want to monitor
3. Start sniffing by clicking the "Start Sniffing" button
4. Filter packets by entering a Python expression in the filter entry
    - The object `pack` represents the packet data
    - Available attributes:
        - `pack["src_ip"]`: Source IP address
        - `pack["src_port"]`: Source port
        - `pack["dst_ip"]`: Destination IP address
        - `pack["dst_port"]`: Destination port
        - `pack["protocol_name"]`: Name of the protocol
        - `pack["process_name"]`: Name of the process associated with the packet
        - `pack["raw_data"]`: Raw data of the packet in hexadecimal format
    - Filter query examples:
        - `pack["src_ip"] == "66.244.22.30" or pack["dst_ip"] == "66.244.22.30"`
5. Apply the filter by clicking the "Apply Filter" button
6. Observe the packets in the text area

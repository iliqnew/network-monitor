import psutil
import json
import tkinter as tk
import tkinter.scrolledtext as scrolledtext
import socket
import struct
import threading
from datetime import datetime as dt

from protocol_strategies import (
    PROTOCOLS
)


class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.text_area.pack(expand=True, fill="both")

        # Entry widget for filtering IP
        self.filter_entry = tk.Entry(root, width=15)
        self.filter_entry.insert(0, "192.168.0.16")  # Default filter IP
        self.filter_entry.pack(pady=10)

        # Button to start packet sniffing
        start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        start_button.pack()

        self.capturing = False

    def start_sniffing(self):
        # Get the filter IP from the entry widget
        self.filter_ip = self.filter_entry.get()

        sniffing_thread = threading.Thread(target=self.sniff_packets)
        sniffing_thread.start()

    def sniff_packets(self):
        self.capturing = not self.capturing
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw_socket.bind(("192.168.0.234", 0))  # Replace with your IP address
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        now = dt.now().strftime('%Y-%m-%d %H-%M-%S')
        try:
            while True:

                try:
                    with open(f'capture-{now}.json', 'r') as f:
                        d = json.load(f)
                except FileNotFoundError:
                    d = []
                except json.decoder.JSONDecodeError:
                    d = []

                if self.capturing: # inappropriate place for this TODO
                    data, addr = raw_socket.recvfrom(65536)
                    decoded_data = self.parse_packet(data)
                    d.append(decoded_data)

                    with open(f"capture-{now}.json", "w") as f:
                        json.dump(d, f, indent=4)

                    self.apply_filters(decoded_data)


        except KeyboardInterrupt:
            print("\nStopping the packet sniffer.")
        finally:
            raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            raw_socket.close()
        f.seek(0, 2)
        json.dump(d, f, indent=4)

    def parse_packet(self, data):
        ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        protocol_id = ip_header[6]
        protocol_name = "Unknown"
        protocol = PROTOCOLS.get(protocol_id)

        if not protocol:
            src_port = dst_port = process_name = "N/A"
        else:
            protocol_name = protocol.name
            src_port, dst_port, process_name = protocol.decode(data)
        return {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol_name": protocol_name,
            "process_name": process_name,
            "raw_data": data.decode("latin-1"),
        }

    def apply_filters(self, data):
        src_ip = data["src_ip"]
        src_port = data["src_port"]
        dst_ip = data["dst_ip"]
        dst_port = data["dst_port"]
        protocol_name = data["protocol_name"]
        process_name = data["process_name"]
        raw_data = data["raw_data"]

        info = f"Src: {src_ip} (Port: {src_port}) -> Dst: {dst_ip} (Port: {dst_port}) | Protocol: {protocol_name} | Process: {process_name}\n"

        # Display the raw data (hexadecimal representation) in the GUI
        raw_data = " ".join(f"{byte:02X}" for byte in raw_data.encode("latin-1"))
        info += f"Raw Data: {raw_data}\n\n"

        # if process_name != "N/A":
        self.text_area.insert(tk.END, info)

        # Scroll to the bottom of the text area
        self.text_area.yview(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    sniffer = PacketSniffer(root)
    root.mainloop()

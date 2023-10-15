import psutil
import tkinter as tk
import tkinter.scrolledtext as scrolledtext
import socket
import struct
import threading


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

    def start_sniffing(self):
        # Get the filter IP from the entry widget
        self.filter_ip = self.filter_entry.get()

        sniffing_thread = threading.Thread(target=self.sniff_packets)
        sniffing_thread.start()

    def sniff_packets(self):
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw_socket.bind(("192.168.0.16", 0))  # Replace with your IP address
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        try:
            while True:
                data, addr = raw_socket.recvfrom(65536)
                self.parse_packet(data)
        except KeyboardInterrupt:
            print("\nStopping the packet sniffer.")
        finally:
            raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            raw_socket.close()

    def parse_packet(self, data):
        ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        protocol = ip_header[6]

        protocol_name = "Unknown"
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
            if len(data) >= 40:  # Ensure we have at least 40 bytes for the TCP header (20 bytes header + 20 bytes options)
                tcp_header = struct.unpack("!HHHH", data[20:28])
                src_port = tcp_header[0]
                dst_port = tcp_header[1]

                # Get process information based on local port (assuming it's the source port)
                try:
                    local_process = psutil.Process(src_port)
                    process_name = local_process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    process_name = "N/A"
            else:
                src_port = dst_port = process_name = "N/A"
        elif protocol == 17:
            protocol_name = "UDP"
            if len(data) >= 28:  # Ensure we have at least 28 bytes for the UDP header
                udp_header = struct.unpack("!HHHH", data[20:28])
                src_port = udp_header[0]
                dst_port = udp_header[1]
                process_name = "N/A"  # Unfortunately, for UDP, it's more challenging to associate with a specific process
            else:
                src_port = dst_port = process_name = "N/A"
        


        info = f"Src: {src_ip} (Port: {src_port}) -> Dst: {dst_ip} (Port: {dst_port}) | Protocol: {protocol_name} | Process: {process_name}\n"

        # Display the raw data (hexadecimal representation) in the GUI
        raw_data = " ".join(f"{byte:02X}" for byte in data)
        info += f"Raw Data: {raw_data}\n\n"

        # if process_name != "N/A":
        self.text_area.insert(tk.END, info)

        # Scroll to the bottom of the text area
        self.text_area.yview(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    sniffer = PacketSniffer(root)
    root.mainloop()




from abc import ABC, abstractclassmethod
import psutil
import struct
from typing import Tuple


class NetworkProtocolStrategy(ABC):
    name: str

    @abstractclassmethod
    def decode(cls, raw_data) -> Tuple[str]:
        ...


class ICMPStrategy(NetworkProtocolStrategy):
    name = "ICMP"

    @classmethod
    def decode(cls, _):
        return "N/A", "N/A", "N/A"


class TCPStrategy(NetworkProtocolStrategy):
    name = "TCP"

    @classmethod
    def decode(cls, raw_data):
        if len(raw_data) >= 40:  # Ensure we have at least 40 bytes for the TCP header (20 bytes header + 20 bytes options)
            tcp_header = struct.unpack("!HHHH", raw_data[20:28])
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

        return src_port, dst_port, process_name


class UDPStrategy(NetworkProtocolStrategy):
    name = "UDP"

    @classmethod
    def decode(cls, raw_data):
        if len(raw_data) >= 28:  # Ensure we have at least 28 bytes for the UDP header
            udp_header = struct.unpack("!HHHH", raw_data[20:28])
            src_port = udp_header[0]
            dst_port = udp_header[1]
            process_name = "N/A"  # Unfortunately, for UDP, it's more challenging to associate with a specific process and I can't think of a way
        else:
            src_port = dst_port = process_name = "N/A"

        return src_port, dst_port, process_name


PROTOCOLS = {
    1: ICMPStrategy,
    6: TCPStrategy,
    17: UDPStrategy
}

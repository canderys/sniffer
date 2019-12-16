import socket
from contextlib import closing
from moduls.Headers import EthernetHeader, Packet


class NetworkSniffer:

    def __init__(self, socket_families=socket.AF_PACKET,
                 proto=socket.ntohs(3), flags=None):
        self.socket_families = socket_families
        self.proto = proto
        self.flags = flags
        try:
            self.condition = self.get_value_flag("condition")
        except ValueError:
            self.condition = ""

    def parse_packet(self, raw_data):
        try:
            ethernet_header = EthernetHeader()
            parsed_ethernet, data = ethernet_header.parse_packet(raw_data)
            parsed_network_layer, data = parsed_ethernet.next_protocol() \
                .parse_packet(data)
            parsed_application_layer, data = parsed_network_layer \
                .next_protocol().parse_packet(data)
            return Packet(ethernet_header, parsed_network_layer,
                          parsed_application_layer, data, raw_data)
        except Exception:
            return None

    def get_value_flag(self, flag):
        return self.flags[self.flags.index(flag) + 1]

    def get_packets(self, max_packets):
        with closing(socket.socket(
                self.socket_families, socket.SOCK_RAW, self.proto)) as conn:
            if "interface" in self.flags:
                interface = self.get_value_flag("interface")
                conn.bind((interface, 0))
            while max_packets:
                raw_data, addr = conn.recvfrom(65536)
                parsed_packet = self.parse_packet(raw_data)
                if parsed_packet and parsed_packet \
                        .check_conditions(self.condition):
                    yield parsed_packet
                    max_packets -= 1

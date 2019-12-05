
import struct
import socket
from contextlib import closing


class NetworkSniffer:

    def __init__(self, proto=socket.ntohs(3)):
        self.proto = proto
        self.TAB1 = '\t - '
        self.TAB2 = '\t\t - '
        self.TAB3 = '\t\t\t - '
        self.TAB4 = '\t\t\t\t - '

        self.DATA_TAB_1 = '\t   '
        self.DATA_TAB_2 = '\t\t   '
        self.DATA_TAB_3 = '\t\t\t   '
        self.DATA_TAB_4 = '\t\t\t\t   '

    def get_ethernet_header(self, data):
        dest_mac, source_mac, ether_type = struct.unpack(
            '! 6s 6s H', data[:14])
        self.dest_mac = self.get_mac_addr(dest_mac)
        self.source_mac = self.get_mac_addr(source_mac)
        self.ether_type = socket.htons(ether_type)
        return data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

    def get_ipv4_packet(self, data):
        version_header_len = data[0]
        self.version = version_header_len >> 4
        self.header_len = (version_header_len & 15) * 4
        self.ttl, self.proto, self.src, self.target = struct.unpack(
            '! 8x B B 2x 4s 4s', data[:20])
        self.src = self.ipv4(self.src)
        self.target = self.ipv4(self.target)
        return data[self.header_len:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def get_icmp_packet(self, data):
        self.icmp_type, self.code, self.checksum = struct.unpack(
            '! B B H', data[:4])
        return data[4:]

    def get_udp_packet(self, data):
        self.src_port_udp, self.dest_port_udp, self.size = struct.unpack(
            '! H H 2x H', data[:8])
        return data[8:]

    def get_TCP_packet(self, data):
        # necessary path header
        self.src_port_tcp, self.dest_port_tcp, self.sequence, \
            self.acknowledgment, self.data_size_and_flags, \
            self.window_size, self.checksum, \
            self.urgent_pointer = struct.unpack(
                '! H H L L H H H H', data[:20])
        bites_data_size_and_flags = bin(self.data_size_and_flags)[2:]
        self.header_size = int(bites_data_size_and_flags[:5], 2)
        flag_sequense = bites_data_size_and_flags[8:]
        self.flag = self.convert_flag(flag_sequense)
        return data[self.header_size:]

    def convert_flag(self, flag_code):
        dict_flags = {
            1: "NS",
            2: "CWR",
            3: "ECE",
            4: "URG",
            5: "ACK",
            6: "PSH",
            7: "RST",
            8: "SYN",
            9: "FIN"
        }
        flags = ""
        for i in range(1, len(flag_code)):
            if flag_code[i] == "1":
                flags += dict_flags[i] + " "
        return flags

    def get_packets(self, max_packets):
        with closing(socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, self.proto)) as conn:
            while max_packets:
                raw_data, addr = conn.recvfrom(65536)
                self.raw_data = raw_data
                data = self.get_ethernet_header(raw_data)
                if self.ether_type == 8:
                    data = self.get_ipv4_packet(data)
                    if self.proto == 1:
                        data = self.get_icmp_packet(data)
                    elif self.proto == 6:
                        self.get_TCP_packet(data)
                    elif self.proto == 17:
                        data = self.get_udp_packet(data)
                self.data = data
                yield self
                max_packets -= 1

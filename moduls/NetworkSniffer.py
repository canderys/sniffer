
import struct
import textwrap
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

    def format_output_line(prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
                return '\n'.join(
                    [prefix + line for line in textwrap.wrap(string, size)])

    def get_TCP_packet(self, raw_data):
        self.src_port_tcp, self.dest_port_tcp, self.sequence, \
            self.acknowledgment, self.flag_urg, self.flag_ack, \
            self.flag_psh, self.flag_rst, self.flag_syn, \
            self.flag_fin = struct.unpack(
                '! H H L L H H H H H H', raw_data[:24])

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
                        self.get_TCP_packet(raw_data)
                    elif self.proto == 17:
                        data = self.get_udp_packet(data)
                self.data = data
                yield self
                max_packets -= 1

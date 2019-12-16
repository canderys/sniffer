import struct
import socket
import ipaddress
from moduls.Postfix import PostfixNotation

ICPM_PROTO = 1
TCP_PROTO = 6
UDP_PROTO = 17


class Packet:
    def __init__(self, link_layer, network_layer, application_layer,
                 data, raw_data):
        self.link_layer = link_layer
        self.network_layer = network_layer
        self.application_layer = application_layer
        self.data = data
        self.proto = network_layer.proto
        self.ether_type = link_layer.ether_type
        self.dest_port = application_layer.dest_port
        self.src_port = application_layer.src_port
        self.src = network_layer.src
        self.target = network_layer.target
        self.raw_data = raw_data
        self.operators = {'host': (4, self.host),
                          'port': (4, self.port),
                          'dst': (4, self.dst),
                          'src': (4, self.src),
                          'and': (1, self.and_funk),
                          '&&': (1, self.and_funk),
                          'or': (2, self.or_funk),
                          '||': (2, self.or_funk),
                          'not': (3, self.and_funk),
                          '!=': (3, self.and_funk)}

    def check_conditions(self, condition):
        postfix = PostfixNotation(self.operators)
        return postfix.get_value(condition)

    def get_protocols(self):
        return self.link_layer, self.network_layer, \
            self.application_layer

    def host(self, stack):
        value = stack.pop()
        return str(self.src) == str(value) or \
            str(self.target) == str(value)

    def port(self, stack):
        value = stack.pop()
        return str(self.src_port) == str(value) or \
            str(self.dest_port) == str(value)

    def dst(self, stack):
        type_dst = stack.pop()
        if type_dst == "host" or type_dst == "port":
            value = stack.pop()
        else:
            value = type_dst
            type_dst = "host"
        if type_dst == "host":
            return str(self.target) == str(value)
        else:
            return str(self.dest_port) == str(value)

    def src(self, stack):
        type_dst = stack.pop()
        if type_dst == "host" or type_dst == "port":
            value = stack.pop()
        else:
            value = type_dst
            type_dst = "host"
        if type_dst == "host":
            return str(self.src) == str(value)
        else:
            return str(self.src_port) == str(value)

    def and_funk(self, stack):
        first = stack.pop()
        second = stack.pop()
        if type(first) != bool:
            stack.push(first)
            first = self.host(stack)
        if type(second) != bool:
            stack.push(second)
            first = self.host(stack)
        return first and second

    def or_funk(self, stack):
        first = stack.pop()
        second = stack.pop()
        if type(first) != bool:
            stack.push(first)
            first = self.host(stack)
        if type(second) != bool:
            stack.push(second)
            first = self.host(stack)
        return first or second

    def not_funk(self, stack):
        first = stack.pop()
        if type(first) != bool:
            stack.push(first)
            first = self.host(stack)
        return not first


class EthernetHeader:
    ipv4_type = socket.ntohs(0x0800)
    ipv6_type = socket.ntohs(0x86DD)

    def parse_packet(self, data):
        dest_mac, source_mac, ether_type = struct.unpack(
            '! 6s 6s H', data[:14])
        self.dest_mac = self.get_mac_addr(dest_mac)
        self.source_mac = self.get_mac_addr(source_mac)
        self.ether_type = socket.htons(ether_type)
        return self, data[14:]

    def get_info(self, flags):
        if "link" not in flags:
            return ""
        if "view" in flags:
            return '{header:17}:\n  {dest:15}:'\
                '{destvalue}\n  {src:15}:{srcvalue}\n  {ether_type:15}'\
                ':{ether_typevalue}\n'.format(header="Ethernet Frame",
                                              dest="Destination",
                                              destvalue=self.dest_mac,
                                              src="Source",
                                              srcvalue=self.source_mac,
                                              ether_type="Ether type",
                                              ether_typevalue=self.ether_type)
        else:
            return 'Ethernet Frame: Destination: {}, Source: {},'\
                'Ether type: {} '.format(
                    self.dest_mac, self.source_mac,
                    self.ether_type)

    def next_protocol(self):
        if self.ether_type == EthernetHeader.ipv4_type:
            return IPv4Header()
        elif self.ether_type == EthernetHeader.ipv6_type:
            return IPv6Header()
        else:
            return None

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr


class IPv4Header:
    IPv4_HDR_LEN = 20

    def parse_packet(self, data):
        version_header_len = data[0]
        self.version = version_header_len >> 4
        self.header_len = (version_header_len & 15) * 4
        self.ttl, self.proto, self.src, self.target = struct.unpack(
            '! 8x B B 2x 4s 4s', data[:IPv4Header.IPv4_HDR_LEN])
        self.src = ipaddress.IPv4Address(self.src)
        self.target = ipaddress.IPv4Address(self.target)
        return self, data[self.header_len:]

    def get_info(self, flags):
        if "view" in flags:
            return '{header:17}:\n'\
                '  {header_len:15}:{len}\n'\
                '  {ttl:15}:{ttl_value}\n'\
                '  {source:15}:{source_value}\n' \
                '  {target:15}:'\
                '{target_value}\n'.format(header="IPV4 Packet",
                                          header_len="Header Length",
                                          len=self.header_len,
                                          ttl="TTL",
                                          ttl_value=self.ttl,
                                          source="Source",
                                          source_value=self.src,
                                          target="Target",
                                          target_value=self.target)
        else:
            return 'IPV4 Packet: Source: {}, Target: {} '.format(
                self.src,
                self.target)

    def next_protocol(self):
        if self.proto == ICPM_PROTO:
            return ICMP()
        elif self.proto == TCP_PROTO:
            return TCP()
        elif self.proto == UDP_PROTO:
            return UDP()
        else:
            return None


class IPv6Header:
    IPv4_UNPACK_PATTERN = '!4xHBB16s16s'
    IPv6_HDR_LEN = 40

    def parse_packet(self, data):
        self.playload_length, self.proto, \
            self.hop_limit, self.src, self.target = struct.unpack(
                IPv6Header.IPv4_UNPACK_PATTERN, data[:IPv6Header.IPv6_HDR_LEN])
        self.src = ipaddress.IPv6Address(self.src)
        self.target = ipaddress.IPv6Address(self.target)
        return self, data[IPv6Header.IPv6_HDR_LEN:]

    def get_info(self, flags):
        if "view" in flags:
            return '{header:17}:\n'\
                '  {playload_len:15}:{len}\n'\
                '  {hop_limit:15}:{limit}\n'\
                '  {source:15}:{src_value}\n'\
                '  {target:15}:{t_value}\n'.\
                format(header="IPV6 Packet",
                       playload_len="Playload length",
                       len=self.playload_length,
                       hop_limit="Hop limit",
                       limit=self.hop_limit,
                       source="Source",
                       src_value=self.src,
                       target="Target",
                       t_value=self.target)
        else:
            return 'IPV6 Packet: Source: {}, Target: {} '.format(
                self.src, self.target)

    def next_protocol(self):
        if self.proto == ICPM_PROTO:
            return ICMP()
        elif self.proto == TCP_PROTO:
            return TCP()
        elif self.proto == UDP_PROTO:
            return UDP()
        else:
            return None


class TCP:
    def parse_packet(self, data):
        # necessary path header
        self.src_port, self.dest_port, self.sequence, \
            self.acknowledgment, self.data_size_and_flags, \
            self.window_size, self.checksum, \
            self.urgent_pointer = struct.unpack(
                '! H H L L H H H H', data[:20])
        bites_data_size_and_flags = bin(self.data_size_and_flags)[2:]
        self.header_size = int(bites_data_size_and_flags[:5], 2)
        flag_sequense = bites_data_size_and_flags[8:]
        self.flag = self.convert_flag(flag_sequense)
        return self, data[self.header_size:]

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

    def get_info(self, flags):
        if "view" in flags:
            ack = "Acknowledgment"
            return '{header:17}:\n'\
                '  {sequence:15}:{seq_value}\n'\
                '  {acknowledgment:15}:{ack_value}\n'\
                '  {flags:15}:{flags_v}\n'\
                '  {source:15}:{source_v}\n'\
                '  {dest:15}:{dest_v}\n'.format(header="TCP Segment",
                                                sequence="Sequence",
                                                seq_value=self.sequence,
                                                acknowledgment=ack,
                                                ack_value=self.acknowledgment,
                                                flags="Flags",
                                                flags_v=self.flag,
                                                source="Source",
                                                source_v=self.src_port,
                                                dest="Destination",
                                                dest_v=self.dest_port)
        else:
            return 'TCP Segment: '\
                'Source Port: {}, Destination Port: {} \n'.format(
                    self.src_port,
                    self.dest_port)


class UDP:
    def parse_packet(self, data):
        self.src_port, self.dest_port, self.size = struct.unpack(
            '! H H 2x H', data[:8])
        return self, data[8:]

    def get_info(self, flags):
        if "view" in flags:
            return '{header:17}:\n'\
                '  {source:15}:{src_value}\n'\
                '  {dest:15}:{dest_value}\n'\
                '  {length:15}:{value}\n'.format(header="UDP Segment",
                                                 source="Source Port",
                                                 src_value=self.src_port,
                                                 dest="Dest Port",
                                                 dest_value=self.dest_port,
                                                 length="Length",
                                                 value=self.size)
        else:
            return 'UDP Segment: Source Port: {},' \
                'Dest Port: {} \n'.format(
                    self.src_port,
                    self.dest_port)


class ICMP:
    def parse_packet(self, data):
        self.icmp_type, self.code, self.checksum = struct.unpack(
            '! B B H', data[:4])
        return self, data[4:]

    def get_info(self, flags):
        if "view" in flags:
            return '{header:17}:\n'\
                '  {type:15}:{type_value}\n'\
                '  {code:15}:{code_value}\n'\
                '  {checksum:15}:{checksum_v}\n'.format(header="ICMP Packet",
                                                        type="Type",
                                                        type_value=self.
                                                        icmp_type,
                                                        code="Code",
                                                        code_value=self.code,
                                                        checksum="Checksum",
                                                        checksum_v=self.
                                                        checksum)
        else:
            return 'ICMP Packet: Type: {}, Code: {} \n'.format(
                self.icmp_type, self.code)

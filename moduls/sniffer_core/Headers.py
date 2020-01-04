import struct
import socket
import ipaddress
from enum import Enum
ICMP_PROTO = 1
ICMP_PROPTO_v6 = 58
TCP_PROTO = 6
UDP_PROTO = 17

PacketStatus = Enum('PacketStatus', ['unsupported', 'end'])


class Packet:
    def __init__(self, link_layer, network_layer, application_layer,
                 data):
        self.link_layer = link_layer
        self.network_layer = network_layer
        self.application_layer = application_layer
        self.data = data
        self.proto = getattr(network_layer, "proto", None)
        self.ether_type = link_layer.ether_type
        self.dest_port = getattr(application_layer, "dest_port", None)
        self.src_port = getattr(application_layer, "src_port", None)
        self.icmp_type = getattr(application_layer, "icmp_type", None)
        self.src = network_layer.src
        self.target = network_layer.target

    def get_protocols(self):
        return [proto for proto in (self.link_layer,
                                    self.network_layer,
                                    self.application_layer) if proto]


class TCP:
    def __init__(self):
        self.tcp_flags = [
            "FIN",
            "SYN",
            "RST",
            "PSH",
            "ACK",
            "URG",
        ]

    def parse_packet(self, data):
        # necessary path header
        self.src_port, self.dest_port, self.sequence, \
            self.ack, self.data_size_and_flags, \
            self.window_size, self.checksum, \
            self.urgent_pointer = struct.unpack(
                '! H H L L H H H H', data[:20])
        self.sequence = self.sequence
        bites_data_size_and_flags = bin(self.data_size_and_flags)[2:]
        self.header_size = int(bites_data_size_and_flags[:4], 2) * 4
        self.flag_sequense = bites_data_size_and_flags[10:]
        self.flag = self.convert_flag()
        return self, data[self.header_size:]

    def convert_flag(self):
        flags = []
        for (bite, flag) in zip(self.flag_sequense[::-1], self.tcp_flags):
            flags.append(flag if bite == '1' else '')
        return " ".join(filter(len, flags))

    def get_info(self, flags):
        if "view" in flags:
            ack = "Acknowledgment"
            return ('{header:17}:\n'
                    '  {sequence:15}: {seq_value}\n'
                    '  {acknowledgment:15}: {ack_v}\n'
                    '  {flags:15}: {flags_v}\n'
                    '  {source:15}: {source_v}\n'
                    '  {dest:15}: {dest_v}\n').format(header="TCP Segment",
                                                      sequence="Sequence",
                                                      seq_value=self.sequence,
                                                      acknowledgment=ack,
                                                      ack_v=self.ack,
                                                      flags="Flags",
                                                      flags_v=self.flag,
                                                      source="Source",
                                                      source_v=self.src_port,
                                                      dest="Destination",
                                                      dest_v=self.dest_port)
        return 'TCP Segment: '\
            'Source Port: {}, Destination Port: {} \n'.format(
                self.src_port,
                self.dest_port)

    def next_protocol(self):
        return PacketStatus.end

    def __str__(self):
        return "tcp"


class UDP:
    def parse_packet(self, data):
        self.src_port, self.dest_port, self.size = struct.unpack(
            '! H H 2x H', data[:8])
        return self, data[8:]

    def get_info(self, flags):
        if "view" in flags:
            return ('{header:17}:\n'
                    '  {source:15}: {src_value}\n'
                    '  {dest:15}: {dest_v}\n'
                    '  {length:15}: {value}\n').format(header="UDP Segment",
                                                       source="Source Port",
                                                       src_value=self.src_port,
                                                       dest="Dest Port",
                                                       dest_v=self.dest_port,
                                                       length="Length",
                                                       value=self.size)
        return 'UDP Segment: Source Port: {},' \
            'Dest Port: {} \n'.format(
                self.src_port,
                self.dest_port)

    def next_protocol(self):
        return PacketStatus.end

    def __str__(self):
        return "udp"


class ICMP:
    def parse_packet(self, data):
        self.icmp_type, self.code, self.checksum = struct.unpack(
            '! B B H', data[:4])
        return self, data[4:]

    def get_info(self, flags):
        if "view" in flags:
            icmp_h = "ICMP Packet"
            chec_s = "Checksum"
            code = self.code
            return ('{header:17}:\n'
                    '  {type:15}: {type_value}\n'
                    '  {code:15}: {code_value}\n'
                    '  {checksum:15}: {checksum_v}\n').format(header=icmp_h,
                                                              type="Type",
                                                              type_value=self.
                                                              icmp_type,
                                                              code="Code",
                                                              code_value=code,
                                                              checksum=chec_s,
                                                              checksum_v=self.
                                                              checksum)
        return 'ICMP Packet: Type: {}, Code: {} \n'.format(
            self.icmp_type, self.code)

    def next_protocol(self):
        return PacketStatus.end

    def __str__(self):
        return "icmp"


class IP:
    def __init__(self):
        self.protocols = {ICMP_PROTO: ICMP(),
                          ICMP_PROPTO_v6: ICMP(),
                          TCP_PROTO: TCP(),
                          UDP_PROTO: UDP()}

    def next_protocol(self):
        if self.proto in self.protocols:
            return self.protocols[self.proto]
        else:
            return PacketStatus.unsupported


class IPv4Header(IP):
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
                '  {header_len:15}: {len}\n'\
                '  {ttl:15}: {ttl_value}\n'\
                '  {source:15}: {source_value}\n' \
                '  {target:15}: '\
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

    def __str__(self):
        return "ipv4"


class IPv6Header(IP):
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
                '  {playload_len:15}: {len}\n'\
                '  {hop_limit:15}: {limit}\n'\
                '  {source:15}: {src_value}\n'\
                '  {target:15}: {t_value}\n'.\
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

    def __str__(self):
        return "ipv6"


class ARPHeader:
    def parse_packet(self, data):
        APR_PATTERN = "!HHBBH6sL6sL"
        arp_detailed = struct.unpack(APR_PATTERN, data[:28])
        self.hard_type = arp_detailed[0]
        self.proto = socket.htons(arp_detailed[1])
        self.hard_size = arp_detailed[2]
        self.proto_size = arp_detailed[3]
        self.opcode = arp_detailed[4]
        self.src = ipaddress.ip_address(arp_detailed[6])
        self.target = ipaddress.ip_address(arp_detailed[8])
        return self, data[28:]

    def get_info(self, flags):
        if "view" in flags:
            return '{header:17}:\n'\
                '  {Proto_type:15}: {proto_type}\n'\
                '  {Hard_type:15}: {htype}\n'\
                '  {source:15}: {src_value}\n'\
                '  {target:15}: {t_value}\n'.\
                format(header="ARP Packet",
                       Hard_type="Hard type",
                       htype=self.hard_type,
                       Proto_type="Proto type",
                       proto_type=self.proto,
                       source="Source",
                       src_value=self.src,
                       target="Target",
                       t_value=self.target)
        else:
            return 'ARP Packet: Source: {}, Target: {} '.format(
                self.src, self.target)

    def next_protocol(self):
        return PacketStatus.end

    def __str__(self):
        return "arp"


class EthernetHeader:
    ether_types = {socket.ntohs(0x0800): IPv4Header(),
                   socket.ntohs(0x86DD): IPv6Header(),
                   socket.ntohs(0x0806): ARPHeader()}

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
            return '{header:17}:\n'\
                '  {dest:15}: {destvalue}\n'\
                '  {src:15}: {srcvalue}\n'\
                '  {ether_type:15}: '\
                '{ether_typevalue}\n'.format(header="Ethernet Frame",
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
        if self.ether_type in EthernetHeader.ether_types:
            return EthernetHeader.ether_types[self.ether_type]
        else:
            return PacketStatus.unsupported

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

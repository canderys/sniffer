import socket
import binascii
from contextlib import closing
from moduls.sniffer_core.Headers import EthernetHeader, Packet, PacketStatus
from moduls.sniffer_core.PacketFilter import PacketFilter
from enum import Enum


PacketType = Enum('PacketType', ["sent", "incoming"])


def network_packets(socket_families=socket.AF_PACKET,
                    proto=socket.ntohs(3),
                    interface=None):
    with closing(socket.socket(
            socket_families, socket.SOCK_RAW, proto)) as conn:
        if interface:
            conn.bind((interface, 0))
        while True:
            yield get_packet_info(conn.recvfrom(65536))


def get_packet_info(packet):
    data = packet[0]
    address = packet[1]
    try:
        pkttype = address[2]
        packet_type = None
        if pkttype == socket.PACKET_OUTGOING:
            packet_type = PacketType.sent
        else:
            packet_type = PacketType.incoming
        return PacketInfo(data, address[0], packet_type)
    except IndexError:
        return PacketInfo(data, address[0], PacketType.incoming)


class PacketInfo:
    def __init__(self, data, interface=None, packet_type=None):
        self.data = data
        self.interface = interface
        self.packet_type = packet_type


class NetworkSniffer:

    def __init__(self, packets_generator=None, flags=None):
        if not flags:
            self.flags = []
        else:
            self.flags = flags
        if not packets_generator:
            if "interface" in self.flags:
                self.packets_generator = network_packets(
                    interface=self.get_value_flag("interface"))
            else:
                self.packets_generator = network_packets()
        else:
            self.packets_generator = packets_generator
        self.condition = ""
        if "condition" in self.flags:
            self.condition = self.get_value_flag("condition")
            self.packetFilter = PacketFilter().compile(self.condition)

    def parse_packet(self, raw_data):
        max_protocols = 3
        proto = EthernetHeader()
        data = raw_data
        protocols = []
        while proto not in (PacketStatus.end, PacketStatus.unsupported):
            parsed_proto, data = proto.parse_packet(data)
            proto = parsed_proto.next_protocol()
            protocols.append(parsed_proto)
        if proto == PacketStatus.end:
            while len(protocols) < max_protocols:
                protocols.append(None)
        if proto == PacketStatus.unsupported:
            return None
        return Packet(*protocols, data)

    def get_value_flag(self, flag):
        return self.flags[flag]

    def get_packets(self, max_packets):
        for packet_info in self.packets_generator:
            parsed_packet = self.parse_packet(packet_info.data)
            if not max_packets:
                return
            if parsed_packet \
                    and (not self.condition or
                         self.packetFilter(parsed_packet)):
                yield parsed_packet, packet_info
                max_packets -= 1

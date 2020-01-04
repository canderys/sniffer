from moduls.sniffer_core import NetworkSniffer, Pcap
from moduls.sniffer_core.NetworkSniffer import get_packet_info, PacketType
import socket
import unittest
import os


class TestSniffer(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(".", "test", "saved_packets")

    def test_get_packet_info(self):
        packet = (b"some, data", ("eth0", 0, socket.PACKET_OTHERHOST))
        packet_info = get_packet_info(packet)
        self.assertEqual(packet_info.packet_type, PacketType.incoming)
        packet = (b"some, data", ("eth0", 0, socket.PACKET_OUTGOING))
        packet_info = get_packet_info(packet)
        self.assertEqual(packet_info.packet_type, PacketType.sent)
        packet = (b"some, data", ("eth0", 0))
        packet_info = get_packet_info(packet)
        self.assertEqual(packet_info.packet_type, PacketType.incoming)

    def test_TCP_parse(self):
        tcp_path = os.path.join(self.path, "tcp_packets", "tcp_packet_1.pcap")
        with open(tcp_path, "rb") \
                as tcp_packet:
            pcap = Pcap()
            for packet in pcap.get_packets_from_pcap(tcp_packet):
                parsed_tcp_packet = NetworkSniffer().parse_packet(packet.data)
            self.assertEqual(str(parsed_tcp_packet.src), "23.35.144.14")
            self.assertEqual(str(parsed_tcp_packet.src_port), "443")

    def test_UDP_parse(self):
        udp_path = os.path.join(self.path, "udp_packets", "udp_packet_1.pcap")
        with open(udp_path, "rb") \
                as udp_packet:
            pcap = Pcap()
            for packet in pcap.get_packets_from_pcap(udp_packet):
                parsed_tcp_packet = NetworkSniffer().parse_packet(packet.data)
            self.assertEqual(str(parsed_tcp_packet.src), "127.0.0.1")
            self.assertEqual(str(parsed_tcp_packet.src_port), "40747")

    def test_ICMP_parse(self):
        icmp_path = os.path.join(
            self.path, "icmp_packets", "icmp_packet_1.pcap")
        with open(icmp_path, "rb") \
                as icmp_packet:
            pcap = Pcap()
            for packet in pcap.get_packets_from_pcap(icmp_packet):
                parsed_icmp_packet = NetworkSniffer().parse_packet(packet.data)
            self.assertEqual(str(parsed_icmp_packet.icmp_type), "8")

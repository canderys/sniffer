import unittest
import math
import os
from moduls.sniffer_core import NetworkSniffer, NetworkWriter, Pcap


class TestNetworkWriter(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(".", "test", "saved_packets")

    def test_view_tcp(self):
        path = os.path.join(self.path, "tcp_packets", "tcp_packet_1.pcap")
        with open(path, "rb") as data:
            pcap = Pcap()
            packets = pcap.get_packets_from_pcap(data)
            network_sniffer = NetworkSniffer(packets)
            network_writer = NetworkWriter(["view", "data"])
            for packet in network_sniffer.get_packets(math.inf):
                packet_info = network_writer.get_packet_info(*packet)
            expected_lines = ["IPV4 Packet      :",
                              "  Header Length  : 20",
                              "  TTL            : 58",
                              "  Source         : 23.35.144.14",
                              "  Target         : 10.155.61.128",
                              "TCP Segment      :",
                              "  Sequence       : 568016820",
                              "  Acknowledgment : 684033442",
                              "  Flags          : ACK",
                              "  Source         : 443",
                              "  Destination    : 45186",
                              "Packet Data      :"]
            actual_lines = packet_info.splitlines()
            self.assertListEqual(expected_lines,
                                 actual_lines[:len(expected_lines)])

    def test_view_udp(self):
        path = os.path.join(self.path, "udp_packets", "udp_packet_1.pcap")
        with open(path, "rb") as data:
            pcap = Pcap()
            packets = pcap.get_packets_from_pcap(data)
            network_sniffer = NetworkSniffer(packets)
            network_writer = NetworkWriter(["view", "data"])
            for packet in network_sniffer.get_packets(math.inf):
                packet_info = network_writer.get_packet_info(*packet)
            expected_lines = ["IPV4 Packet      :",
                              "  Header Length  : 20",
                              "  TTL            : 64",
                              "  Source         : 127.0.0.1",
                              "  Target         : 127.0.0.53",
                              "UDP Segment      :",
                              "  Source Port    : 40747",
                              "  Dest Port      : 53",
                              "  Length         : 65143",
                              "Packet Data      :"]
            actual_lines = packet_info.splitlines()
            self.assertListEqual(expected_lines,
                                 actual_lines[:len(expected_lines)])

    def test_view_icmp(self):
        path = os.path.join(
            self.path, "icmp_packets", "icmp_packet_1.pcap")
        with open(path, "rb") as data:
            pcap = Pcap()
            packets = pcap.get_packets_from_pcap(data)
            network_sniffer = NetworkSniffer(packets)
            network_writer = NetworkWriter(["view", "data"])
            for packet in network_sniffer.get_packets(math.inf):
                packet_info = network_writer.get_packet_info(*packet)
            expected_lines = ["IPV4 Packet      :",
                              "  Header Length  : 20",
                              "  TTL            : 64",
                              "  Source         : 10.155.61.128",
                              "  Target         : 5.255.255.80",
                              "ICMP Packet      :",
                              "  Type           : 8",
                              "  Code           : 0",
                              "  Checksum       : 9913",
                              "Packet Data      :"]
            actual_lines = packet_info.splitlines()
            self.assertListEqual(expected_lines,
                                 actual_lines[:len(expected_lines)])

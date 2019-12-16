from moduls.Pcap import Pcap
import unittest


class TestSniffer(unittest.TestCase):
    def test_TCP_parse(self):
        with open("./test/tcp_packets/tcp_packet_1.pcap", "rb") as tcp_packet:
            pcap = Pcap(tcp_packet, "r")
            for packet in pcap.get_packets_from_pcap():
                print(1)
                parsed_tcp_packet = packet
            self.assertEqual(str(parsed_tcp_packet.src), "192.168.0.22")
            self.assertEqual(str(parsed_tcp_packet.src_port), "44358")

    def test_UDP_parse(self):
        with open("./test/udp_packets/udp_packet_1.pcap", "rb") as tcp_packet:
            pcap = Pcap(tcp_packet, "r")
            for packet in pcap.get_packets_from_pcap():
                print(1)
                parsed_tcp_packet = packet
            self.assertEqual(str(parsed_tcp_packet.src), "127.0.0.1")
            self.assertEqual(str(parsed_tcp_packet.src_port), "35475")

import binascii


class NetworkWriter:
    def __init__(self, flags=None):
        self.flags = flags
        self.TAB1 = '\t - '
        self.TAB2 = '\t\t - '
        self.TAB3 = '\t\t\t - '
        self.TAB4 = '\t\t\t\t - '

        self.DATA_TAB_1 = '\t   '
        self.DATA_TAB_2 = '\t\t   '
        self.DATA_TAB_3 = '\t\t\t   '
        self.DATA_TAB_4 = '\t\t\t\t   '

    def get_packet_info(self, parsed_packet):
        sniffed_data = ""
        sniffed_data += self.get_ethernet_info(parsed_packet)
        if parsed_packet.ether_type == 8:
            sniffed_data += self.get_ipv4_info(parsed_packet)
            if parsed_packet.proto == 1:
                sniffed_data += self.get_icmp_info(parsed_packet)
            elif parsed_packet.proto == 6:
                sniffed_data += self.get_tpc_info(parsed_packet)
            elif parsed_packet.proto == 17:
                sniffed_data += self.get_udp_info(parsed_packet)
            else:
                sniffed_data += self.TAB1 + 'IPv4'
                if "data" in self.flags:
                    sniffed_data += "Data: " + self.format_output_line(
                        self.DATA_TAB_2, parsed_packet.data)
        else:
            if "data" in self.flags:
                sniffed_data += 'Ethernet Data:'
                sniffed_data += self.format_output_line(
                    self.DATA_TAB_1, parsed_packet.data)
        return sniffed_data

    def get_ethernet_info(self, parsed_packet):
        if "link" not in self.flags:
            return ""
        data = ""
        data += '\n Ethernet Frame: '
        data += self.TAB1 + \
            'Destination: {}, Source: {}, Protocol: {} '.format(
                parsed_packet.dest_mac, parsed_packet.source_mac,
                parsed_packet.ether_type)
        return data

    def get_ipv4_info(self, parsed_packet):
        data = ""
        data += self.TAB1 + "IPV4 Packet:"
        if "view" in self.flags:
            data += self.TAB2 + \
                'Version: {}, Header Length: {}, TTL: {}'.format(
                    parsed_packet.version, parsed_packet.header_len,
                    parsed_packet.ttl)
        data += self.TAB3 + \
            'protocol: {}, Source: {}, Target: {}'.format(
                parsed_packet.proto, parsed_packet.src,
                parsed_packet.target)
        return data

    def get_icmp_info(self, parsed_packet):
        data = ""
        data += self.TAB1 + 'ICMP Packet'
        if "view" in self.flags:
            data += self.TAB2 + \
                'Type: {}, Code: {}, Checksum: {},'.format(
                    parsed_packet.icmp_type, parsed_packet.code,
                    parsed_packet.checksum)
        if "data" in self.flags:
            data += self.TAB2 + 'ICMP Data:'
            data += self.format_output_line(
                self.DATA_TAB_3, parsed_packet.data)
        return data

    def get_tpc_info(self, parsed_packet):
        data = ""
        data += self.TAB1 + 'TCP Segment:'
        data += self.TAB2 + \
            'Source Port: {}, Destination Port: {}'.format(
                parsed_packet.src_port_tcp,
                parsed_packet.dest_port_tcp)
        if "view" in self.flags:
            data += self.TAB2 + \
                'Sequence: {}, Acknowledgment: {}'.format(
                    parsed_packet.sequence, parsed_packet.acknowledgment)
            data += self.TAB2 + 'Flags:'
            data += self.TAB3 + parsed_packet.flag
        if "data" in self.flags:
            data += self.TAB2 + 'TCP Data:'
            data += self.format_output_line(
                self.DATA_TAB_3, parsed_packet.data)
        return data

    def get_udp_info(self, parsed_packet):
        data = ""
        data += self.TAB1 + 'UDP Segment:'
        data += self.TAB2 + \
            'Source Port: {}, Destination Port: {}, Length: {}'.format(
                parsed_packet.src_port_udp,
                parsed_packet.dest_port_udp,
                parsed_packet.size)
        if "data" in self.flags:
            data += self.TAB2 + 'UDP Data:'
            data += self.format_output_line(
                self.DATA_TAB_3, parsed_packet.data)
        return data

    def format_output_line(self, prefix, bytes_data):
        return prefix + str(binascii.hexlify(bytes_data))

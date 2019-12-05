import textwrap


class NetworkWriter:
    def __init__(self, flags=None):
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
        sniffed_data += '\n Ethernet Frame: '
        sniffed_data += self.TAB1 + \
            'Destination: {}, Source: {}, Protocol: {} '.format(
                parsed_packet.dest_mac, parsed_packet.source_mac,
                parsed_packet.ether_type)

        if parsed_packet.ether_type == 8:
            sniffed_data += self.TAB1 + "IPV4 Packet:"
            sniffed_data += self.TAB2 + \
                'Version: {}, Header Length: {}, TTL: {}'.format(
                    parsed_packet.version, parsed_packet.header_len,
                    parsed_packet.ttl)
            sniffed_data += self.TAB3 + \
                'protocol: {}, Source: {}, Target: {}'.format(
                    parsed_packet.proto, parsed_packet.src,
                    parsed_packet.target)

            if parsed_packet.proto == 1:
                sniffed_data += self.TAB1 + 'ICMP Packet:'
                sniffed_data += self.TAB2 + \
                    'Type: {}, Code: {}, Checksum: {},'.format(
                        parsed_packet.icmp_type, parsed_packet.code,
                        parsed_packet.checksum)
                sniffed_data += self.TAB2 + 'ICMP Data:'
                sniffed_data += self.format_output_line(
                    self.DATA_TAB_3, parsed_packet.data)
            elif parsed_packet.proto == 6:
                sniffed_data += self.TAB1 + 'TCP Segment:'
                sniffed_data += self.TAB2 + \
                    'Source Port: {}, Destination Port: {}'.format(
                        parsed_packet.src_port_tcp,
                        parsed_packet.dest_port_tcp)
                sniffed_data += self.TAB2 + \
                    'Sequence: {}, Acknowledgment: {}'.format(
                        parsed_packet.sequence, parsed_packet.acknowledgment)
                sniffed_data += self.TAB2 + 'Flags:'
                sniffed_data += self.TAB3 + \
                    'URG: {}, ACK: {}, PSH: {}'.format(
                        parsed_packet.flag_urg,
                        parsed_packet.flag_ack,
                        parsed_packet.flag_psh)
                sniffed_data += self.TAB3 + \
                    'RST: {}, SYN: {}, FIN:{}'.format(
                        parsed_packet.flag_rst,
                        parsed_packet.flag_syn,
                        parsed_packet.flag_fin)
                sniffed_data += self.TAB2 + 'TCP Data:'
                sniffed_data += self.format_output_line(
                    self.DATA_TAB_3, parsed_packet.data)
            elif parsed_packet.proto == 17:
                sniffed_data += self.TAB1 + 'UDP Segment:'
                sniffed_data += self.TAB2 + \
                    'Source Port: {}, Destination Port: {}, Length: {}'.format(
                        parsed_packet.src_port_udp,
                        parsed_packet.dest_port_udp,
                        parsed_packet.size)

            else:
                sniffed_data += self.TAB1 + 'IPv4 Data:'
                sniffed_data += self.format_output_line(self.DATA_TAB_2, parsed_packet.data)

        else:
            sniffed_data += 'Ethernet Data:'
            sniffed_data += self.format_output_line(self.DATA_TAB_1, parsed_packet.data)
        return sniffed_data

    def get_sniffed_data(self, raw_data):
        data = self.get_ethernet_header(raw_data)
        sniffed_data = ""
        sniffed_data += '\n Ethernet Frame: '
        sniffed_data += self.TAB1 + \
            'Destination: {}, Source: {}, Protocol: {} '.format(
                self.dest_mac, self.source_mac, self.ether_type)

        if self.ether_type == 8:
            data = self.get_ipv4_packet(data)
            sniffed_data += self.TAB1 + "IPV4 Packet:"
            sniffed_data += self.TAB2 + \
                'Version: {}, Header Length: {}, TTL: {}'.format(
                    self.version, self.header_len, self.ttl)
            sniffed_data += self.TAB3 + \
                'protocol: {}, Source: {}, Target: {}'.format(
                    self.proto, self.src, self.target)

            if self.proto == 1:
                data = self.get_icmp_packet(data)
                sniffed_data += self.TAB1 + 'ICMP Packet:'
                sniffed_data += self.TAB2 + \
                    'Type: {}, Code: {}, Checksum: {},'.format(
                        self.icmp_type, self.code, self.checksum)
                sniffed_data += self.TAB2 + 'ICMP Data:'
                sniffed_data += self.format_output_line(self.DATA_TAB_3, data)
            elif self.proto == 6:
                self.get_TCP_packet(raw_data)
                sniffed_data += self.TAB1 + 'TCP Segment:'
                sniffed_data += self.TAB2 + \
                    'Source Port: {}, Destination Port: {}'.format(
                        self.src_port_tcp, self.dest_port_tcp)
                sniffed_data += self.TAB2 + \
                    'Sequence: {}, Acknowledgment: {}'.format(
                        self.sequence, self.acknowledgment)
                sniffed_data += self.TAB2 + 'Flags:'
                sniffed_data += self.TAB3 + \
                    'URG: {}, ACK: {}, PSH: {}'.format(
                        self.flag_urg, self.flag_ack, self.flag_psh)
                sniffed_data += self.TAB3 + \
                    'RST: {}, SYN: {}, FIN:{}'.format(
                        self.flag_rst, self.flag_syn, self.flag_fin)
                sniffed_data += self.TAB2 + 'TCP Data:'
                sniffed_data += self.format_output_line(self.DATA_TAB_3, data)
            elif self.proto == 17:
                data = self.get_udp_packet(data)
                sniffed_data += self.TAB1 + 'UDP Segment:'
                sniffed_data += self.TAB2 + \
                    'Source Port: {}, Destination Port: {}, Length: {}'.format(
                        self.src_port_udp, self.dest_port_udp, self.size)

            else:
                sniffed_data += self.TAB1 + 'IPv4 Data:'
                sniffed_data += self.format_output_line(self.DATA_TAB_2, data)

        else:
            sniffed_data += 'Ethernet Data:'
            if data:
                sniffed_data += self.format_output_line(self.DATA_TAB_1, data)
        return sniffed_data

    def format_output_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join([r'\x{:02x}'.format(byte) for byte in string])
            return '\n'.join(
                [prefix + line for line in textwrap.wrap(string, size)])

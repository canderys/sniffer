import binascii


class NetworkWriter:
    def __init__(self, flags=None):
        self.flags = flags

    def get_packet_info(self, parsed_packet):
        output_list = []
        output_list.append(self.get_ethernet_info(parsed_packet))
        if parsed_packet.ether_type == 8:
            output_list.append(self.get_ipv4_info(parsed_packet))
            if parsed_packet.proto == 1:
                output_list.append(self.get_icmp_info(parsed_packet))
            elif parsed_packet.proto == 6:
                output_list.append(self.get_tpc_info(parsed_packet))
            elif parsed_packet.proto == 17:
                output_list.append(self.get_udp_info(parsed_packet))
        return self.format_output(output_list)

    def format_output(self, output_list, width=50):
        output_list = list(filter(len, output_list))
        if len(output_list):
            return "".join(output_list) + "\n"
        return ""

    def get_ethernet_info(self, parsed_packet):
        if "link" not in self.flags:
            return ""
        data = ""
        data += 'Ethernet Frame: '
        data += 'Destination: {}, Source: {}, Protocol: {} '.format(
                parsed_packet.dest_mac, parsed_packet.source_mac,
                parsed_packet.ether_type)
        return data

    def get_ipv4_info(self, parsed_packet):
        data = ""
        data += "IPV4 Packet: "
        if "view" in self.flags:
            data += 'Version: {}, Header Length: {}, TTL: {}, '.format(
                    parsed_packet.version, parsed_packet.header_len,
                    parsed_packet.ttl)
        data += 'protocol: {}, Source: {}, Target: {} '.format(
                parsed_packet.proto, parsed_packet.src,
                parsed_packet.target)
        return data

    def get_icmp_info(self, parsed_packet):
        data = ""
        data += 'ICMP Packet '
        if "view" in self.flags:
            data += 'Type: {}, Code: {}, Checksum: {},'.format(
                    parsed_packet.icmp_type, parsed_packet.code,
                    parsed_packet.checksum)
        if "data" in self.flags:
            data += 'ICMP Data:'
            data += self.format_output_data(parsed_packet.data)
        return data

    def get_tpc_info(self, parsed_packet):
        data = ""
        data += 'TCP Segment: '
        data += 'Source Port: {}, Destination Port: {} '.format(
                parsed_packet.src_port_tcp,
                parsed_packet.dest_port_tcp)
        if "view" in self.flags:
            data += 'Sequence: {}, Acknowledgment: {} '.format(
                    parsed_packet.sequence, parsed_packet.acknowledgment)
            data += 'Flags: '
            data += parsed_packet.flag
        if "data" in self.flags:
            data += '  TCP Data:  '
            data += self.format_output_data(parsed_packet.data)
        return data

    def get_udp_info(self, parsed_packet):
        data = ""
        data += ' UDP Segment: '
        data += 'Source Port: {}, Destination Port: {}, Length: {}'.format(
                parsed_packet.src_port_udp,
                parsed_packet.dest_port_udp,
                parsed_packet.size)
        if "data" in self.flags:
            data += 'UDP Data:'
            data += self.format_output_data(parsed_packet.data)
        return data

    def format_output_data(self, bytes_data):
        return str(binascii.hexlify(bytes_data))

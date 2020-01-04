import binascii
from moduls.sniffer_core.NetworkSniffer import PacketType
from termcolor import colored


def dec_to_base(N, base):
    if not hasattr(dec_to_base, 'table'):
        dec_to_base.table = '0123456789abcdef'
    x, y = divmod(N, base)
    return dec_to_base(x, base) + dec_to_base.table[y] \
        if x else dec_to_base.table[y]


def hexdump(src, length=16):
    return "".join([chr(x) if 0x20 <= x < 0x7F else "." for x in src])


class NetworkWriter:
    def __init__(self, flags=None):
        self.flags = flags

    def get_packet_info(self, parsed_packet, packet_info):
        self.output_list = []
        for layer in parsed_packet.get_protocols():
            self.output_list.append(layer.get_info(self.flags))
        if "data" in self.flags:
            self.output_list.append(self.format_output_data(
                parsed_packet.data, self.flags))
        output = self.format_output()
        packet_type = getattr(packet_info, "packet_type", None)
        if "color" in self.flags and packet_type:
            if packet_type == PacketType.sent:
                return colored(output, "red")
            if packet_type == PacketType.incoming:
                return colored(output, "blue")
        return output

    def format_output(self, width=50):
        return "".join(filter(len, self.output_list)) + "\n"

    def format_output_data(self, bytes_data, flags, octets=8):
        max_len = 9 + octets * 5
        hexdump_str = hexdump(bytes_data)
        if len(bytes_data) == 0:
            return ""
        output_list = []
        data = str(binascii.hexlify(bytes_data))[2:-1]
        if "view" in self.flags:
            output_list.append("{header:17}:".format(header="Packet Data"))
        else:
            output_list.append("Data : ")
        number_line = 0
        curent_octets = 0
        output = dec_to_base(number_line, 16).rjust(7, '0') + "  "
        start = 0
        for i in range(0, len(data), 4):
            output += data[i:i + 4] + " "
            curent_octets += 1
            if curent_octets == octets:
                number_line += 16
                output += " " + hexdump_str[start:start + 16]
                start += 16
                output_list.append(output)
                output = dec_to_base(number_line, 16).rjust(7, '0') + "  "
                curent_octets = 0
        if len(output) > 9:
            spaces_count = max_len - len(output)
            last_path = hexdump_str[start:start + 16]
            output += " " + last_path.rjust(spaces_count + len(last_path))
            output_list.append(output)
        return "\n".join(output_list) + "\n"

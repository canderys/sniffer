import binascii


def dec_to_base(N, base):
    if not hasattr(dec_to_base, 'table'):
        dec_to_base.table = '0123456789abcdef'
    x, y = divmod(N, base)
    return dec_to_base(x, base) + dec_to_base.table[y] \
        if x else dec_to_base.table[y]


class NetworkWriter:
    def __init__(self, flags=None):
        self.flags = flags

    def get_packet_info(self, parsed_packet):
        output_list = []
        for layer in parsed_packet.get_protocols():
            output_list.append(layer.get_info(self.flags))
        if "data" in self.flags:
            output_list.append(self.format_output_data(
                parsed_packet.data, self.flags))
        return self.format_output(output_list)

    def format_output(self, output_list, width=50):
        output_list = list(filter(len, output_list))
        if len(output_list):
            return "".join(output_list) + "\n"
        return ""

    def format_output_data(self, bytes_data, flags, octets=8):
        data = str(binascii.hexlify(bytes_data))[2:-1]
        if not data:
            return ""
        output = ""
        if "view" in self.flags:
            output += "{header:17}:\n".format(header="Packet Data")
        else:
            output += "data : \n"
        number_line = 0
        curent_octets = 0
        output += dec_to_base(number_line, 16).rjust(7, '0') + " "
        for i in range(0, len(data), 4):
            output += data[i:i + 4] + " "
            curent_octets += 1
            if i + 4 == len(data):
                break
            if curent_octets == octets:
                output += "\n"
                number_line += 16
                output += dec_to_base(number_line, 16).rjust(7, '0') + " "
                curent_octets = 0
        return output + "\n"

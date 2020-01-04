from moduls.Postfix import PostfixNotation, OperationInfo
from moduls.sniffer_core.exceptions import SnifferError
import ipaddress
import functools


class IncorrectFilterError(SnifferError):
    CODE = 5


def boolean(func):
    @functools.wraps(func)
    def wrapper(*args):
        for argument in args[1:]:
            if argument not in (True, False):
                raise IncorrectFilterError(
                    "Incorrect argument {}".format(argument))
        return func(*args)
    return wrapper


class PacketFilter:
    def __init__(self, interpreter=PostfixNotation.get_interpreter):
        self.packet_operators = ['src.port', 'dst.port',
                                 'src.host', 'dst.host', 'proto', 'net.proto']
        self.logic_operators = ['==', 'and', '&&', 'or', '||', 'not', '!=']
        self.operators = {'src.port': OperationInfo(4, self.src_port, 0),
                          'dst.port': OperationInfo(4, self.dst_port, 0),
                          'src.host': OperationInfo(4, self.src_host, 0),
                          'dst.host': OperationInfo(4, self.dst_host, 0),
                          'proto': OperationInfo(4, self.proto, 0),
                          'net.proto': OperationInfo(4, self.net_proto, 0),
                          '==': OperationInfo(3, self.equal, 2),
                          'and': OperationInfo(1, self._and, 2),
                          '&&': OperationInfo(1, self._and, 2),
                          'or': OperationInfo(2, self._or, 2),
                          '||': OperationInfo(2, self._or, 2),
                          'not': OperationInfo(3, self._not, 1),
                          '!=': OperationInfo(3, self.not_eq, 2)}
        self.interpreter = interpreter(self.operators)
        self.validation_dict = {ipaddress.IPv6Address: (ipaddress.ip_address,
                                                        "IP address"),
                                ipaddress.IPv4Address: (ipaddress.ip_address,
                                                        "IP address"),
                                int: (int, "positive integer")}

    def compile(self, condition):
        condition = condition.replace('(', ' ( ')
        condition = condition.replace(')', ' ) ')
        condition_tokens = condition.split()
        used_packet_operators = False
        used_logic_operators = False
        for token in condition_tokens:
            if not used_packet_operators and \
                    token in self.packet_operators:
                used_packet_operators = True
            if not used_logic_operators and \
                    token in self.logic_operators:
                used_logic_operators = True
        if not (used_packet_operators and used_logic_operators):
            raise IncorrectFilterError("Error : Incorrect filter")
        try:
            self.interpreter.preprocessing(condition)
        except Exception as e:
            raise IncorrectFilterError(str(e))
        return self.get_filter

    def get_filter(self, packet):
        self.packet = packet
        if self.packet:
            try:
                return self.interpreter.calculate()
            except Exception as e:
                raise IncorrectFilterError(str(e))
        else:
            return False

    def src_port(self):
        return self.packet.src_port

    def dst_port(self):
        return self.packet.dest_port

    def src_host(self):
        return self.packet.src

    def dst_host(self):
        return self.packet.target

    def proto(self):
        return str(self.packet.application_layer)

    def net_proto(self):
        return str(self.packet.network_layer)

    def equal(self, a, b):
        validation_type = None
        determined, checked = (b, a) if isinstance(a, str) else (a, b)
        for cur_type in self.validation_dict:
            if isinstance(determined, cur_type):
                validation_type = cur_type
        if validation_type:
            type_info = self.validation_dict[validation_type]
            converter = type_info[0]
            try:
                return converter(determined) == converter(checked)
            except Exception:
                message = "Error : expected {}, but was : {}".format(
                    type_info[1], checked)
                raise IncorrectFilterError(message)
        else:
            return str(a) == str(b)

    @boolean
    def _and(self, a, b):
        return a and b

    @boolean
    def _or(self, a, b):
        return a or b

    @boolean
    def _not(self, a):
        return not a

    @boolean
    def not_eq(self, a, b):
        return a != b

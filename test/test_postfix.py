import unittest
from moduls.Postfix import PostfixNotation, PostfixError, OperationInfo


def reverse(a):
    return int(str(a)[::-1])


def sum(a, b):
    return int(a) + int(b)


def mul(a, b):
    return int(a) * int(b)


class TestPostfix(unittest.TestCase):
    def test_convert_to_postfix(self):
        operators = {'+': OperationInfo(1, sum, 2),
                     '*': OperationInfo(2, mul, 2)}

        postfix = PostfixNotation(operators)
        self.assertEqual(['1', '2', '45', '7', '2', '*', '+',
                          '*', '+'],
                         postfix.to_postfix("1 + 2 * ( 45 + 7 * 2 )"))

    def test_calculate_value(self):
        operators = {'+': OperationInfo(1, sum, 2),
                     '*': OperationInfo(2, mul, 2),
                     'rev value': OperationInfo(3, reverse, 1)}
        postfix = PostfixNotation(operators)
        value = postfix.get_value("123 + 65 * 32 * ( 21 + rev value 32 )")
        self.assertEqual(91643, value)

    def wrong_input(self):
        operators = {'+': OperationInfo(1, sum, 2),
                     '*': OperationInfo(2, mul, 2),
                     'rev value': OperationInfo(3, reverse, 1)}
        postfix = PostfixNotation(operators)
        postfix.get_value("+ + +")

    def test_wrong_input(self):
        self.assertRaises(PostfixError, self.wrong_input)

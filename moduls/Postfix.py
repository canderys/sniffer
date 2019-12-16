from pythonds.basic.stack import Stack


class PostfixNotation:
    def __init__(self, operations_dict):
        self.operations_dict = operations_dict

    def to_postfix(self, expression):
        stack = Stack()
        postfixList = []
        self.operations_dict['('] = (0,)
        current_operand = ""
        for current_operand in expression.split():
            if current_operand in self.operations_dict:
                if current_operand == '(':
                    stack.push(current_operand)
                else:
                    priority = self.operations_dict[current_operand][0]
                    while not stack.isEmpty() and \
                            self.operations_dict[stack.peek()][0] >= priority:
                        print(stack.peek())
                        postfixList.append(stack.pop())
                    stack.push(current_operand)
            elif current_operand == ')':
                operand_in_stack = stack.pop()
                while operand_in_stack != '(':
                    postfixList.append(operand_in_stack)
                    operand_in_stack = stack.pop()
            else:
                postfixList.append(current_operand)
        else:
            while not stack.isEmpty():
                postfixList.append(stack.pop())
        print(postfixList)
        return postfixList

    def calculate_variable(self, postfix_variable):
        stack = Stack()
        for token in postfix_variable:
            if token in self.operations_dict:
                function = self.operations_dict[token][1]
                stack.push(function(stack))
            else:
                stack.push(token)
        return stack.pop()

    def get_value(self, expression):
        if not expression:
            return True
        postfix = self.to_postfix(expression)
        return self.calculate_variable(postfix)


def sum(stack):
    first = stack.pop()
    second = stack.pop()
    return int(first) + int(second)


def mul(stack):
    first = stack.pop()
    second = stack.pop()
    return int(first) * int(second)


if __name__ == '__main__':

    OPERATORS = {'+': (1, sum), '-': (1, lambda x, y: x - y),
                 '*': (2, mul), '/': (2, lambda x, y: x / y)}
    postfix = PostfixNotation(OPERATORS)
    print(postfix.calculate_variable(postfix.to_postfix("1 + 2 * 6")))

import functools


def get_in_stack(func):
    @functools.wraps(func)
    def wrapper(stack, count_args, name):
        args_list = []
        for i in range(count_args):
            try:
                args_list.append(stack.pop())
            except IndexError:
                raise PostfixError(
                    "Error : not enough arguments for : {}".format(name))
        return func(*args_list)
    return wrapper


class PostfixError(Exception):
    pass


class OperationInfo:
    def __init__(self, priority, operation=None, args_count=None):
        self.priority = priority
        self.operation = operation
        self.args_count = args_count


class PostfixNotation:
    def __init__(self, operations_dict):
        self.operations_dict = {}
        self.verbose_operations = {}
        self.max_words = 0
        for operation in operations_dict:
            operation_info = operations_dict[operation]
            operation_info.operation = get_in_stack(operation_info.operation)
            self.operations_dict[operation] = operation_info
            operation_tokens = operation.split()
            if len(operation_tokens) > 1:
                self.max_words = max(self.max_words, len(operation_tokens))
                self.verbose_operations[operation] = \
                    self.operations_dict[operation]

    @staticmethod
    def get_interpreter(operations):
        return PostfixNotation(operations)

    def preprocessing(self, condition):
        self.postfix_cond = self.to_postfix(condition)

    def calculate(self):
        return self.calculate_variable(self.postfix_cond)

    def to_postfix(self, expression):
        stack = []
        postfixList = []
        self.operations_dict['('] = OperationInfo(0)
        current_operand = ""
        tokens_array = expression.split()
        i = 0
        while i < len(tokens_array):
            current_operand = tokens_array[i]
            operation_words = 1
            while i < len(tokens_array) - 1 and \
                    operation_words <= self.max_words and \
                    current_operand + " " + tokens_array[i + 1] \
                    in self.verbose_operations:
                current_operand = current_operand + " " + tokens_array[i + 1]
                operation_words += 1
                i += 1
            if current_operand in self.operations_dict:
                if current_operand == '(':
                    stack.append(current_operand)
                else:
                    pr = self.operations_dict[current_operand].priority
                    while stack and \
                            self.operations_dict[stack[-1]].priority >= pr:
                        postfixList.append(stack.pop())
                    stack.append(current_operand)
            elif current_operand == ')':
                try:
                    operand_in_stack = stack.pop()
                except IndexError:
                    raise PostfixError("Error : missing open bracket")
                while operand_in_stack != '(':
                    postfixList.append(operand_in_stack)
                    try:
                        operand_in_stack = stack.pop()
                    except IndexError:
                        raise PostfixError("Error : missing open bracket")
            else:
                postfixList.append(current_operand)
            i += 1
        else:
            while stack:
                postfixList.append(stack.pop())
        return postfixList

    def calculate_variable(self, postfix_variable):
        stack = []
        for token in postfix_variable:
            if token == '(':
                raise PostfixError("Error : missing closing bracket")
            if token in self.operations_dict:
                function_info = self.operations_dict[token]
                function = function_info.operation
                count_args = function_info.args_count
                stack.append(function(stack, count_args, token))
            else:
                stack.append(token)
        if len(stack) != 1:
            raise PostfixError("Error : unused operands detected")
        return stack.pop()

    def get_value(self, expression):
        postfix = self.to_postfix(expression)
        return self.calculate_variable(postfix)

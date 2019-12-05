class SnifferError(Exception):
    pass


class IncorrectInputError(SnifferError):
    def __init__(self, message):
        SnifferError.__init__(self, message)
        self.code = 1


class IncorrectOsError(SnifferError):
    def __init__(self, message):
        SnifferError.__init__(self, message)
        self.code = 3

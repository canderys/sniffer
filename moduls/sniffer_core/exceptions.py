class SnifferError(Exception):
    pass


class IncorrectInputError(SnifferError):
    CODE = 1


class IncorrectOsError(SnifferError):
    CODE = 3


class ParsingArgsError(SnifferError):
    CODE = 4

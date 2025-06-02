import java.lang


class SpaceNames(object):
    """
    Reserved AddressSpace names across architectures and associated attributes
    """

    CONSTANT_SPACE_INDEX: int = 0
    CONSTANT_SPACE_NAME: unicode = u'const'
    FSPEC_SPACE_NAME: unicode = u'fspec'
    IOP_SPACE_NAME: unicode = u'iop'
    JOIN_SPACE_NAME: unicode = u'join'
    OTHER_SPACE_INDEX: int = 1
    OTHER_SPACE_NAME: unicode = u'OTHER'
    STACK_SPACE_NAME: unicode = u'stack'
    UNIQUE_SPACE_NAME: unicode = u'unique'
    UNIQUE_SPACE_SIZE: int = 4



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


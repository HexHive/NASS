import java.lang


class AddressUtils(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def unsignedAdd(__a0: long, __a1: long) -> long: ...

    @staticmethod
    def unsignedCompare(__a0: long, __a1: long) -> int: ...

    @staticmethod
    def unsignedSubtract(__a0: long, __a1: long) -> long: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


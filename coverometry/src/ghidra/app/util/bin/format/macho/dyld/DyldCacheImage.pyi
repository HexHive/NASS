import java.lang


class DyldCacheImage(object):
    """
    A convenience interface for getting the address and path of a DYLD Cache image
    """









    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> long:
        """
        Gets the address the start of the image
        @return The address of the start of the image
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getPath(self) -> unicode:
        """
        Gets the path of the image
        @return The path of the image
        """
        ...

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

    @property
    def address(self) -> long: ...

    @property
    def path(self) -> unicode: ...
import java.lang


class NameTransformer(object):
    """
    Interface to transform (shorten, simplify) names of data-types, functions, and name spaces
     for display.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def simplify(self, input: unicode) -> unicode:
        """
        Return a transformed version of the given input.  If no change is made, the original
         String object is returned.
        @param input is the name to transform
        @return the transformed version
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


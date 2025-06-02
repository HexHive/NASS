import ghidra.app.decompiler
import java.awt
import java.lang


class ColorProvider(object):
    """
    Functional interface to allow us to map a token to a color.
 
     This class allows us to avoid the namespace conflicts of Java's Function and Ghidra's
     Function since we can declare a  as a parameter to methods instead of
     a Function.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getColor(self, token: ghidra.app.decompiler.ClangToken) -> java.awt.Color:
        """
        Returns a color for the given token
        @param token the token
        @return the color
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


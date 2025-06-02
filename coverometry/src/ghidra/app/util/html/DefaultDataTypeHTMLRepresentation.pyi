from typing import List
import ghidra.app.util.html
import java.lang


class DefaultDataTypeHTMLRepresentation(ghidra.app.util.html.HTMLDataTypeRepresentation):




    def __init__(self, dataType: ghidra.program.model.data.DataType): ...



    def diff(self, otherRepresentation: ghidra.app.util.html.HTMLDataTypeRepresentation) -> List[ghidra.app.util.html.HTMLDataTypeRepresentation]: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFullHTMLContentString(self) -> unicode:
        """
        This is like {@link #getHTMLString()}, but does not put HTML tags around the data
        @return the content
        """
        ...

    def getFullHTMLString(self) -> unicode:
        """
        Returns an HTML string for this data representation object
        @return the html
        @see #getHTMLString()
        """
        ...

    def getHTMLContentString(self) -> unicode:
        """
        This is like {@link #getHTMLString()}, but does not put HTML tags around the data
        @return the content
        """
        ...

    def getHTMLString(self) -> unicode:
        """
        Returns an HTML string for this data representation object.  The HTML returned will be
         truncated if it is too long.   To get the full HTML, call {@link #getFullHTMLString()}.
        @return the html
        @see #getFullHTMLString()
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


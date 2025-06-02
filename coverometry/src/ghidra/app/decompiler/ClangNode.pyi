from typing import List
import ghidra.app.decompiler
import ghidra.program.model.address
import java.awt
import java.lang


class ClangNode(object):
    """
    A collection of source code text elements, with associated attributes, grouped in
     a tree structure.
    """









    def Child(self, i: int) -> ghidra.app.decompiler.ClangNode:
        """
        Get the i-th child grouping
        @param i is the index selecting the grouping
        @return the selected grouping
        """
        ...

    def Parent(self) -> ghidra.app.decompiler.ClangNode:
        """
        Get the immediate grouping (parent) containing this text element. If this is a
         complete document, null is returned.
        @return the parent grouping or null
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def flatten(self, __a0: List[object]) -> None: ...

    def getClangFunction(self) -> ghidra.app.decompiler.ClangFunction:
        """
        Get the text representing an entire function of which this is part.
        @return text for the whole function
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the biggest Program address associated with the code that this text represents
        @return the biggest Address
        """
        ...

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the smallest Program address associated with the code that this text represents
        @return the smallest Address
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def numChildren(self) -> int:
        """
        Return the number of immediate groupings this text breaks up into
        @return the number of child groupings
        """
        ...

    def setHighlight(self, c: java.awt.Color) -> None:
        """
        Set a highlighting background color for all text elements
        @param c is the color to set
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def clangFunction(self) -> ghidra.app.decompiler.ClangFunction: ...

    @property
    def highlight(self) -> None: ...  # No getter available.

    @highlight.setter
    def highlight(self, value: java.awt.Color) -> None: ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address: ...
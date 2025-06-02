from typing import List
import ghidra.app.decompiler
import ghidra.program.model.listing
import java.lang


class PrettyPrinter(object):
    """
    This class is used to convert a C/C++ language
     token group into readable C/C++ code.
    """

    INDENT_STRING: unicode = u' '



    def __init__(self, function: ghidra.program.model.listing.Function, tokgroup: ghidra.app.decompiler.ClangTokenGroup, transformer: ghidra.program.model.symbol.NameTransformer):
        """
        Constructs a new pretty printer using the specified C language token group.
         The printer takes a NameTransformer that will be applied to symbols, which can replace
         illegal characters in the symbol name for instance. A null indicates no transform is applied.
        @param function is the function to be printed
        @param tokgroup the C language token group
        @param transformer the transformer to apply to symbols
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFunction(self) -> ghidra.program.model.listing.Function: ...

    def getLines(self) -> List[ghidra.app.decompiler.ClangLine]:
        """
        Returns an array list of the C language lines contained in the
         C language token group.
        @return an array list of the C language lines
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def print(self) -> ghidra.app.decompiler.DecompiledFunction:
        """
        Prints the C language token group
         into a string of C code.
        @return a string of readable C code
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
    def function(self) -> ghidra.program.model.listing.Function: ...

    @property
    def lines(self) -> java.util.ArrayList: ...
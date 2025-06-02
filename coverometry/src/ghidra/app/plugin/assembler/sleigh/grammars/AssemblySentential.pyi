from typing import Iterator
from typing import List
import ghidra.app.plugin.assembler.sleigh.grammars
import ghidra.app.plugin.assembler.sleigh.symbol
import ghidra.app.plugin.assembler.sleigh.tree
import java.io
import java.lang
import java.util
import java.util.function


class AssemblySentential(object, java.lang.Comparable, java.lang.Iterable):
    """
    A "string" of symbols
 
 
     To avoid overloading the word "string", we call this a "sentential". Technically, to be a
     "sentential" in the classic sense, it must be a possible element in the derivation of a sentence
     in the grammar starting with the start symbol. We ignore that if only for the sake of naming.
    """

    WHITE_SPACE: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyStringTerminal = _




    class TruncatedWhiteSpaceParseToken(ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential.WhiteSpaceParseToken):




        def __init__(self, __a0: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, __a1: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal): ...



        def equals(self, __a0: object) -> bool: ...

        def generateString(self) -> unicode: ...

        def getClass(self) -> java.lang.Class: ...

        def getGrammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar: ...

        def getParent(self) -> ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch: ...

        def getString(self) -> unicode: ...

        def getSym(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol: ...

        def hashCode(self) -> int: ...

        def isConstructor(self) -> bool: ...

        def isNumeric(self) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def print(self, __a0: java.io.PrintStream) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class WhiteSpaceParseToken(ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken):




        def __init__(self, __a0: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, __a1: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal, __a2: unicode): ...



        def equals(self, __a0: object) -> bool: ...

        def generateString(self) -> unicode: ...

        def getClass(self) -> java.lang.Class: ...

        def getGrammar(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar: ...

        def getParent(self) -> ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch: ...

        def getString(self) -> unicode: ...

        def getSym(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol: ...

        def hashCode(self) -> int: ...

        def isConstructor(self) -> bool: ...

        def isNumeric(self) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def print(self, __a0: java.io.PrintStream) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    @overload
    def __init__(self):
        """
        Construct a blank string
 
         This is suitable as a blank start, to add new symbols, or to use directly as the RHS,
         effectively creating an "epsilon" production.
        """
        ...

    @overload
    def __init__(self, syms: List[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol]):
        """
        Construct a string from any number of symbols
        @param syms
        """
        ...

    @overload
    def __init__(self, __a0: List[object]): ...

    def __iter__(self): ...

    def addCommaWS(self) -> None:
        """
        Add a comma followed by optional whitespace.
        """
        ...

    def addSeparatorPart(self, str: unicode) -> None:
        """
        Add a syntactic terminal element, but with consideration for optional whitespace surrounding
         special characters
        @param str the expected terminal
        """
        ...

    def addSeparators(self, str: unicode) -> None:
        """
        Add a syntactic terminal element, but considering that commas contained within may be
         followed by optional whitespace
        @param str the expected terminal
        """
        ...

    def addSymbol(self, symbol: ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol) -> bool:
        """
        Add a symbol to the right of this sentential
        @param symbol the symbol to add
        @return true
        """
        ...

    def addWS(self) -> bool:
        """
        Add optional whitespace, if not already preceded by whitespace
        @return true if whitespace was added
        """
        ...

    @overload
    def compareTo(self, that: ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def finish(self) -> None:
        """
        Trim leading and trailing whitespace, and make the sentential immutable
        """
        ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getSymbol(self, pos: int) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol: ...

    def getSymbols(self) -> List[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol]:
        """
        Get the symbols in this sentential
        @return the symbols;
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def size(self) -> int:
        """
        Get the number of symbols, including whitespace, in this sentential
        @return the number of symbols
        """
        ...

    def spliterator(self) -> java.util.Spliterator: ...

    def sub(self, fromIndex: int, toIndex: int) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def symbols(self) -> List[object]: ...
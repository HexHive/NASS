import ghidra.app.plugin.assembler.sleigh.symbol
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang
import java.util


class AssemblyNumericSymbols(object):
    """
    A context to hold various symbols offered to the assembler, usable where numbers are expected.
    """

    EMPTY: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols = ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols@46f03598
    languageLabels: java.util.NavigableMap
    programEquates: java.util.NavigableMap







    def choose(self, name: unicode, space: ghidra.program.model.address.AddressSpace) -> java.util.Set:
        """
        Choose a symbol with the given name, using the space as a hint
 
         <p>
         If a space is not given, or if that space is the constant space, then this will choose from
         all symbols, via {@link #chooseAll(String)}. If a space is given, and it is not the constant
         space, then this will choose from symbols in the given space, via
         {@link #chooseBySpace(String, AddressSpace)}.
        @param name the name
        @param space the address space, or null
        @return the equate value, or label addressable word offset, or null
        """
        ...

    def chooseAll(self, name: unicode) -> java.util.Set:
        """
        Choose any symbol with the given name
 
         <p>
         This will order equates first, then program labels, then language labels. For addresses, the
         value is its addressable word offset.
        @param name the name
        @return the value, or null
        """
        ...

    def chooseBySpace(self, name: unicode, space: ghidra.program.model.address.AddressSpace) -> java.util.Set:
        """
        Choose a label with the given name in the given space
        @param name the name
        @param space the address space
        @return the addressable word offset of the found label, or null
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromLanguage(language: ghidra.program.model.lang.Language) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols:
        """
        Get symbols from a language, when no program is available
        @param language the language
        @return the symbols
        """
        ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols:
        """
        Get symbols from a program (and its language)
        @param program the program
        @return the symbols
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getSuggestions(self, got: unicode, space: ghidra.program.model.address.AddressSpace, max: int) -> java.util.Collection:
        """
        Suggest up to max symbols having the given prefix, using space as a hint
 
         <p>
         As in {@link #chooseAll(String)}, if space is null or the constant space, then this will
         suggest from all symbols, via {@link #suggestAny(String, int)}. If space is given, and it is
         not the constant space, then this will suggest from symbols in the given space, via
         {@link #suggestBySpace(String, AddressSpace, int)}.
        @param got the prefix
        @param space the space, or null
        @param max the maximum number of symbols to suggest
        @return the collection of symbol names
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def suggestAny(self, got: unicode, max: int) -> java.util.Collection:
        """
        Suggest up to max symbols having the given prefix
        @param got the prefix
        @param max the maximum number of symbols to suggest
        @return the collection of symbol names
        """
        ...

    def suggestBySpace(self, got: unicode, space: ghidra.program.model.address.AddressSpace, max: int) -> java.util.Collection:
        """
        Suggest up to max symbols from the given space having the given prefix
        @param got the prefix
        @param space the address space
        @param max the maximum number of symbols to suggest
        @return the collection of symbol names
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


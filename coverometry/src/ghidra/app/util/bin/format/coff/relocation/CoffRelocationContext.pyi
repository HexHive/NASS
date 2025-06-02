import ghidra.app.util.bin.format.coff
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang
import java.util.function


class CoffRelocationContext(object):
    """
    CoffRelocationContext provide COFF relocation context data to be used by 
     CoffRelocationHandler during processing of relocations.
    """





    def __init__(self, program: ghidra.program.model.listing.Program, header: ghidra.app.util.bin.format.coff.CoffFileHeader, symbolsMap: java.util.Map):
        """
        Construct COFF relocation context
        @param program program to which relocations are applied
        @param header COFF file header
        @param symbolsMap symbol lookup map
        """
        ...



    def computeContextValueIfAbsent(self, key: unicode, mappingFunction: java.util.function.Function) -> object:
        """
        Get and optionally compute context value for specified key
        @param key extension-specific context key
        @param mappingFunction function used to compute value if absent
        @return context value
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getContextValue(self, key: unicode) -> object:
        """
        Get context value for specified key
        @param key extension-specific key
        @return context value or null if absent
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get program to which relocations are being applied
        @return program
        """
        ...

    def getSection(self) -> ghidra.app.util.bin.format.coff.CoffSectionHeader:
        """
        Get COFF section to which relocations are being applied
        @return COFF section
        """
        ...

    def getSymbol(self, relocation: ghidra.app.util.bin.format.coff.CoffRelocation) -> ghidra.program.model.symbol.Symbol:
        """
        Get symbol required to process a relocation.  Method should only be invoked
         when a symbol is required since some relocations may not require a symbol.
        @param relocation relocation whose related symbol should be returned
        @return relocation symbol
        @throws RelocationException if symbol not found
        """
        ...

    def getSymbolAddress(self, relocation: ghidra.app.util.bin.format.coff.CoffRelocation) -> ghidra.program.model.address.Address:
        """
        Get address of symbol required to process a relocation.  Method should only be invoked
         when a symbol is required since some relocations may not require a symbol.
        @param relocation relocation whose related symbol should be returned
        @return relocation symbol
        @throws RelocationException if symbol not found
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def putContextValue(self, key: unicode, value: object) -> None:
        """
        Store context value for specified key
        @param key extension-specific context key
        @param value context value
        """
        ...

    def resetContext(self, coffSection: ghidra.app.util.bin.format.coff.CoffSectionHeader) -> None:
        """
        Reset context at start of COFF section relocation processing
        @param coffSection COFF section
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
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def section(self) -> ghidra.app.util.bin.format.coff.CoffSectionHeader: ...
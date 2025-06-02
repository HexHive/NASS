import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.util
import java.lang


class AddressLabelInfo(object, java.lang.Comparable):
    """
    AddressLabelInfo is a utility class for storing
     an Address together with a corresponding language-defined 
     label or alias that is within the global namespace which is
     established with a SourceType of IMPORTED within a program.
    """





    def __init__(self, addr: ghidra.program.model.address.Address, sizeInBytes: int, label: unicode, isPrimary: bool, isEntry: bool, type: ghidra.program.model.util.ProcessorSymbolType, isVolatile: bool):
        """
        Constructor for class AddressLabelInfo
        @param addr Address object that describes the memory address
        @param sizeInBytes Integer describing the Size in bytes that the label applies to.
        @param label String label or alias for the Address
        @param isPrimary boolean describes if this object is the primary label for the Address 'addr'
        @param isEntry boolean describes if this object is an entry label for the Address 'addr'
        @param type ProcessorSymbolType the type of symbol
        @param isVolatile Boolean describes if the memory at this address is volatile
        """
        ...



    @overload
    def compareTo(self, info: ghidra.program.model.lang.AddressLabelInfo) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the object's address.
        """
        ...

    def getByteSize(self) -> int:
        """
        Returns the object's size in bytes. Always non-zero positive value and defaults to 
         addressable unit size of associated address space.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the object's end address.
        """
        ...

    def getLabel(self) -> unicode:
        """
        Returns the object's label or alias.
        """
        ...

    def getProcessorSymbolType(self) -> ghidra.program.model.util.ProcessorSymbolType:
        """
        Returns the type of processor symbol (if this was defined by a pspec) or null if this
         is not a processor symbol or it was not specified in the pspec file.  It basically allows
         a pspec file to give more information about a symbol such as if code or a code pointer is
         expected to be at the symbol's address.
        @return the ProcesorSymbolType if it has one.
        """
        ...

    def hashCode(self) -> int: ...

    def isEntry(self) -> bool: ...

    def isPrimary(self) -> bool:
        """
        Returns whether the object is the primary label at the address.
        """
        ...

    def isVolatile(self) -> bool:
        """
        Returns whether the object is volatile.
         Boolean.False when the address is explicitly not volatile.
         Boolean.True when the address is volatile.
         NULL when the volatility is not defined at this address.
        """
        ...

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
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def byteSize(self) -> int: ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def entry(self) -> bool: ...

    @property
    def label(self) -> unicode: ...

    @property
    def primary(self) -> bool: ...

    @property
    def processorSymbolType(self) -> ghidra.program.model.util.ProcessorSymbolType: ...
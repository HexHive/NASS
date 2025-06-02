import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang


class SymbolEntry(object):
    """
    A mapping from a HighSymbol object to the storage that holds the symbol's value.
    """





    def __init__(self, sym: ghidra.program.model.pcode.HighSymbol):
        """
        Constructor for use with restoreXML
        @param sym is the symbol owning this entry
        """
        ...



    def decode(self, decoder: ghidra.program.model.pcode.Decoder) -> None:
        """
        Decode this entry from the stream. Typically more than one element is consumed.
        @param decoder is the stream decoder
        @throws DecoderException for invalid encodings
        """
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode this entry as (a set of) elements to the given stream
        @param encoder is the stream encoder
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPCAdress(self) -> ghidra.program.model.address.Address:
        """
        The storage used to hold this Symbol may be used for other purposes at different points in
         the code.  This returns the earliest address in the code where this storage is used for this symbol
        @return the starting address where the Symbol uses this storage
        """
        ...

    def getSize(self) -> int:
        """
        Get the number of bytes consumed by the symbol when using this storage
        @return the size of this entry
        """
        ...

    def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
        """
        Get the storage associated with this particular mapping of the Symbol
        @return the storage object
        """
        ...

    def hashCode(self) -> int: ...

    def isReadOnly(self) -> bool:
        """
        @return true if the mapped storage is read-only
        """
        ...

    def isVolatile(self) -> bool:
        """
        @return true if the mapped storage is volatile
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
    def PCAdress(self) -> ghidra.program.model.address.Address: ...

    @property
    def readOnly(self) -> bool: ...

    @property
    def size(self) -> int: ...

    @property
    def storage(self) -> ghidra.program.model.listing.VariableStorage: ...

    @property
    def volatile(self) -> bool: ...
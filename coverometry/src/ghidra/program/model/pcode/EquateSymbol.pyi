import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import java.lang


class EquateSymbol(ghidra.program.model.pcode.HighSymbol):
    FORMAT_BIN: int = 4
    FORMAT_CHAR: int = 5
    FORMAT_DEC: int = 2
    FORMAT_DEFAULT: int = 0
    FORMAT_DOUBLE: int = 7
    FORMAT_FLOAT: int = 6
    FORMAT_HEX: int = 1
    FORMAT_OCT: int = 3



    @overload
    def __init__(self, func: ghidra.program.model.pcode.HighFunction): ...

    @overload
    def __init__(self, uniqueId: long, conv: int, val: long, func: ghidra.program.model.pcode.HighFunction, addr: ghidra.program.model.address.Address, hash: long): ...

    @overload
    def __init__(self, uniqueId: long, nm: unicode, val: long, func: ghidra.program.model.pcode.HighFunction, addr: ghidra.program.model.address.Address, hash: long): ...



    @staticmethod
    def convertName(nm: unicode, val: long) -> int:
        """
        Determine what format a given equate name is in.
         Integer format conversions are stored using an Equate object, where the name of the equate
         is the actual conversion String. So the only way to tell what kind of conversion is being performed
         is by examining the name of the equate.  The format code of the conversion is returned, or if
         the name is not a conversion,  FORMAT_DEFAULT is returned indicating a normal String equate.
        @param nm is the name of the equate
        @param val is the value being equated
        @return the format code for the conversion or FORMAT_DEFAULT if not a conversion
        """
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder) -> None: ...

    @staticmethod
    def decodeMapSym(decoder: ghidra.program.model.pcode.Decoder, isGlobal: bool, high: ghidra.program.model.pcode.HighFunction) -> ghidra.program.model.pcode.HighSymbol:
        """
        Restore a full HighSymbol from the next &lt;mapsym&gt; element in the stream.
         This method acts as a HighSymbol factory, instantiating the correct class
         based on the particular elements.
        @param decoder is the stream decoder
        @param isGlobal is true if this symbol is being read into a global scope
        @param high is the function model that will own the new symbol
        @return the new symbol
        @throws DecoderException for invalid encodings
        """
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None: ...

    @staticmethod
    def encodeMapSym(encoder: ghidra.program.model.pcode.Encoder, sym: ghidra.program.model.pcode.HighSymbol) -> None:
        """
        Encode the given symbol with all its mapping as a &lt;mapsym&gt; element to the stream.
        @param encoder is the stream encoder
        @param sym is the given symbol
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getCategoryIndex(self) -> int:
        """
        For parameters (category=0), this method returns the position of the parameter within the function prototype.
        @return the category index for this symbol
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getConvert(self) -> int: ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        @return the data-type associate with this symbol
        """
        ...

    def getFirstWholeMap(self) -> ghidra.program.model.pcode.SymbolEntry:
        """
        @return the first mapping object attached to this symbol
        """
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        """
        Get the function model of which this symbol is a part.
        @return the HighFunction owning this symbol
        """
        ...

    def getHighVariable(self) -> ghidra.program.model.pcode.HighVariable:
        """
        Get the HighVariable associate with this symbol if any.  The symbol may have multiple
         partial HighVariables associated with it. This method returns the biggest one, which
         may not be the same size as the symbol itself.
        @return the associated HighVariable or null
        """
        ...

    def getId(self) -> long:
        """
        Get id associated with this symbol.
        @return the id
        """
        ...

    def getName(self) -> unicode:
        """
        Get the base name of this symbol
        @return the name
        """
        ...

    def getNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        Fetch the namespace owning this symbol, if it exists.
        @return the Namespace object or null
        """
        ...

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the first code Address, within the function, where this symbol's storage actually
         holds the value of the symbol.  If there is more than one mapping for the symbol, this
         returns the code Address for the first mapping.  A null value indicates that the storage
         is valid over the whole function (at least). If the value is non-null, the symbol storage
         may be used for other purposes at prior locations.
        @return the first use code Address or null
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the Program object containing the function being modeled.
        @return the Program
        """
        ...

    def getSize(self) -> int:
        """
        @return the number of bytes consumed by the storage for this symbol
        """
        ...

    def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
        """
        @return the storage associated with this symbol (associated with the first mapping)
        """
        ...

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Fetch the corresponding database Symbol if it exists.
        @return the matching Symbol object or null
        """
        ...

    def getValue(self) -> long: ...

    def hashCode(self) -> int: ...

    def isGlobal(self) -> bool:
        """
        Is this symbol in the global scope or some other global namespace
        @return true if this is global
        """
        ...

    def isHiddenReturn(self) -> bool:
        """
        @return true is symbol holds a pointer to where a function's return value should be stored
        """
        ...

    def isIsolated(self) -> bool:
        """
        If this returns true, the decompiler will not speculatively merge this with
         other variables.
         Currently, being isolated is equivalent to being typelocked.
        @return true if this will not be merged with other variables
        """
        ...

    def isNameLocked(self) -> bool:
        """
        If this returns true, this symbol's name is "locked". meaning the decompiler
         is forced to use the name when labeling the storage described by this symbol.
        @return true if the name is considered "locked".
        """
        ...

    def isParameter(self) -> bool:
        """
        Is this symbol a parameter for a function
        @return true if this is a parameter
        """
        ...

    def isReadOnly(self) -> bool:
        """
        @return true if the symbol's value is considered read-only (by the decompiler)
        """
        ...

    def isThisPointer(self) -> bool:
        """
        @return true if symbol is a "this" pointer for a class method
        """
        ...

    def isTypeLocked(self) -> bool:
        """
        If this returns true, this symbol's data-type is "locked", meaning
         it is considered unchangeable during decompilation. The data-type
         will be forced into the decompiler's model of the function to the extent possible.
        @return true if the data-type is considered "locked".
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setNameLock(self, namelock: bool) -> None:
        """
        Set whether this symbol's name is considered "locked". If it is "locked", the decompiler
         will use the name when labeling the storage described by this symbol.
        @param namelock is true if the name should be considered "locked".
        """
        ...

    def setTypeLock(self, typelock: bool) -> None:
        """
        Set whether this symbol's data-type is considered "locked". If it is "locked",
         this symbol's data-type is considered unchangeable during decompilation. The data-type
         will be forced into the decompiler's model of the function to the extent possible.
        @param typelock is true if the data-type should be considered "locked".
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
    def convert(self) -> int: ...

    @property
    def value(self) -> long: ...
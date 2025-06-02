from typing import Iterator
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import java.lang
import java.util


class LocalSymbolMap(object):
    """
    A container for local symbols within the decompiler's model of a function. It contains HighSymbol
     objects for any symbol within the scope of the function, including parameters. The container is populated
     either from the underlying Function object (when sending information to the decompiler) or read in from
     an XML description (when receiving a function model from the decompiler). HighSymbols can be obtained
     via Address using findLocal() or by id using getSymbol().  Parameters can be accessed specifically
     using getParamSymbol().
    """





    def __init__(self, highFunc: ghidra.program.model.pcode.HighFunction, spc: ghidra.program.model.address.AddressSpace):
        """
        @param highFunc HighFunction the local variables are defined within.
        @param spc the address space the local variables are defined within.
        """
        ...



    def decodeScope(self, decoder: ghidra.program.model.pcode.Decoder) -> None:
        """
        Decode a local symbol scope from the stream
        @param decoder is the stream decoder
        @throws DecoderException for invalid encodings
        """
        ...

    def decodeSymbolList(self, decoder: ghidra.program.model.pcode.Decoder) -> None:
        """
        Add mapped symbols to this LocalVariableMap, by decoding the &lt;symbollist&gt; and &lt;mapsym&gt; elements
        @param decoder is the stream decoder
        @throws DecoderException for invalid encodings
        """
        ...

    def encodeLocalDb(self, encoder: ghidra.program.model.pcode.Encoder, namespace: ghidra.program.model.symbol.Namespace, transformer: ghidra.program.model.symbol.NameTransformer) -> None:
        """
        Encode all the variables in this local variable map to the stream
        @param encoder is the stream encoder
        @param namespace if the namespace of the function
        @param transformer is used to compute a simplified version of the namespace name
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def findLocal(self, addr: ghidra.program.model.address.Address, pc: ghidra.program.model.address.Address) -> ghidra.program.model.pcode.HighSymbol:
        """
        Find any local variable (including input params) by address
        @param addr - variable storage address
        @param pc = Address of first use, or null if address
                     is valid throughout the entire scope
        @return HighLocal or null
        """
        ...

    @overload
    def findLocal(self, store: ghidra.program.model.listing.VariableStorage, pc: ghidra.program.model.address.Address) -> ghidra.program.model.pcode.HighSymbol:
        """
        Find any local variable (including input params) by address
        @param store - variable storage
        @param pc = Address of first use, or null if address
                     is valid throughout the entire scope
        @return HighLocal or null
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        """
        Get the decompiler's function model owning this container
        @return the owning HighFunction
        """
        ...

    def getNameToSymbolMap(self) -> java.util.Map:
        """
        Construct and return a map from a HighSymbol's name to the HighSymbol object
        @return the new name to symbol map
        """
        ...

    def getNumParams(self) -> int:
        """
        Get the number of parameter symbols in this scope
        @return the number of parameters
        """
        ...

    def getParam(self, i: int) -> ghidra.program.model.pcode.HighParam:
        """
        @param i is the desired parameter position
        @return the i-th parameter variable
        """
        ...

    def getParamSymbol(self, i: int) -> ghidra.program.model.pcode.HighSymbol:
        """
        @param i is the desired parameter position
        @return the i-th parameter HighSymbol
        """
        ...

    def getSymbol(self, id: long) -> ghidra.program.model.pcode.HighSymbol:
        """
        Lookup high variable based upon its symbol-id
        @param id symbol-id
        @return variable or null if not found
        """
        ...

    def getSymbols(self) -> Iterator[ghidra.program.model.pcode.HighSymbol]:
        """
        Get all the symbols mapped for this program, Param, Locals.
         The HighSymbol can either be a HighParam, or HighLocal
        @return an iterator over all mapped symbols.
        """
        ...

    def grabFromFunction(self, includeDefaultNames: bool) -> None:
        """
        Populate the local variable map from information attached to the Program DB's function.
        @param includeDefaultNames is true if default symbol names should be considered locked
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

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction: ...

    @property
    def nameToSymbolMap(self) -> java.util.Map: ...

    @property
    def numParams(self) -> int: ...

    @property
    def symbols(self) -> java.util.Iterator: ...
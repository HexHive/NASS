from typing import List
import ghidra.app.decompiler
import ghidra.app.decompiler.DecompileCallback
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang


class DecompileCallback(object):
    """
    Routines that the decompiler invokes to gather info during decompilation of a
     function.
    """

    MAX_SYMBOL_COUNT: int = 16




    class StringData(object):
        byteData: List[int]



        def __init__(self, __a0: unicode, __a1: int): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

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



    def __init__(self, prog: ghidra.program.model.listing.Program, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, dt: ghidra.program.model.pcode.PcodeDataTypeManager): ...



    @staticmethod
    def encodeInstruction(encoder: ghidra.program.model.pcode.Encoder, addr: ghidra.program.model.address.Address, ops: List[ghidra.program.model.pcode.PcodeOp], fallthruoffset: int, paramshift: int, addrFactory: ghidra.program.model.address.AddressFactory) -> None:
        """
        Encode a list of pcode, representing an entire Instruction, to the stream
        @param encoder is the stream encoder
        @param addr is the Address to associate with the Instruction
        @param ops is the pcode ops
        @param fallthruoffset number of bytes after instruction start that pcode
                    flow falls into
        @param paramshift special instructions for injection use
        @param addrFactory is the address factory for recovering address space names
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBytes(self, addr: ghidra.program.model.address.Address, size: int) -> List[int]:
        """
        Get bytes from the program's memory image.
         Any exceptions are caught, resulting in null being returned. The decompiler treats a null
         as a DataUnavailError but will continue to process the function.
        @param addr is the starting address to fetch bytes from
        @param size is the number of bytes to fetch
        @return the bytes matching the query or null if the query can't be met
        """
        ...

    def getCPoolRef(self, refs: List[long], resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Look up details of a specific constant pool reference
        @param refs is the constant id (which may consist of multiple integers)
        @param resultEncoder will contain the reference details
        @throws IOException for errors in the underlying stream while encoding results
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeLabel(self, addr: ghidra.program.model.address.Address) -> unicode:
        """
        Return the first symbol name at the given address
        @param addr is the given address
        @return the symbol or null if no symbol is found
        @throws IOException for errors trying to encode the symbol
        """
        ...

    def getComments(self, addr: ghidra.program.model.address.Address, types: int, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Collect any/all comments for the function starting at the indicated
         address.  Filter based on selected comment types.
        @param addr is the indicated address
        @param types is the set of flags
        @param resultEncoder will contain the collected comments
        @throws IOException for errors in the underlying stream
        """
        ...

    def getDataType(self, name: unicode, id: long, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Get a description of a data-type given its name and type id
        @param name is the name of the data-type
        @param id is the type id
        @param resultEncoder will contain the resulting description
        @throws IOException for errors in the underlying stream while encoding
        """
        ...

    def getExternalRef(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Get a description of an external reference at the given address
        @param addr is the given address
        @param resultEncoder will contain the resulting description
        @throws IOException for errors encoding the result
        """
        ...

    def getMappedSymbols(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Describe data or functions at the given address; either function, reference, data, or hole.
         Called by the native decompiler to query the GHIDRA database about any
         symbols at the given address.
        @param addr is the given address
        @param resultEncoder is where to write encoded description
        @throws IOException for errors encoding the result
        """
        ...

    def getNamespacePath(self, id: long, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Write a description of the formal namespace path to the given namespace
        @param id is the ID of the given namespace
        @param resultEncoder is where to write the encoded result
        @throws IOException for errors in the underlying stream
        """
        ...

    def getNativeMessage(self) -> unicode:
        """
        @return the last message from the decompiler
        """
        ...

    def getPcode(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.PackedEncode) -> None:
        """
        Generate p-code ops for the instruction at the given address.
         Any exceptions are caught, resulting in an empty result. The decompiler interprets these
         as a BadDataError, but will continue to process the function.
        @param addr is the given address
        @param resultEncoder will contain the generated p-code ops
        """
        ...

    def getPcodeInject(self, nm: unicode, paramDecoder: ghidra.program.model.pcode.Decoder, type: int, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Generate p-code ops for a named injection payload
        @param nm is the name of the payload
        @param paramDecoder contains the context
        @param type is the type of payload
        @param resultEncoder will contain the generated p-code ops
        @throws DecoderException for problems decoding the injection context
        @throws UnknownInstructionException if there is no instruction at the injection site
        @throws IOException for errors encoding the injection result
        @throws NotFoundException if an expected aspect of the injection is not present in context
        @throws MemoryAccessException for problems establishing the injection context
        """
        ...

    def getRegister(self, name: unicode, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Return a description of the register with the given name
        @param name is the given name
        @param resultEncoder is where to write the description
        @throws IOException for errors writing to the underlying stream
        """
        ...

    def getRegisterName(self, addr: ghidra.program.model.address.Address, size: int) -> unicode:
        """
        Given a storage location, return the register name for that location, or null if there
         is no register there.
        @param addr is the starting address of the storage location
        @param size is the size of storage in bytes
        @return the register name or null
        """
        ...

    def getStringData(self, addr: ghidra.program.model.address.Address, maxChars: int, dtName: unicode, dtId: long) -> ghidra.app.decompiler.DecompileCallback.StringData:
        """
        Check for a string at the given address and return a UTF8 encoded byte array.
         If there is already data present at the address, use this to determine the
         string encoding. Otherwise use the data-type info passed in to determine the encoding.
         Check that the bytes at the address represent a valid string encoding that doesn't
         exceed the maximum character limit passed in.  Return null if the string is invalid.
         Return the string translated into a UTF8 byte array otherwise.  A (valid) empty
         string is returned as a zero length array.
        @param addr is the given address
        @param maxChars is the maximum character limit
        @param dtName is the name of a character data-type
        @param dtId is the id associated with the character data-type
        @return the UTF8 encoded byte array or null
        """
        ...

    def getTrackedRegisters(self, addr: ghidra.program.model.address.Address, resultEncoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Get "tracked" register values, constant values associated with a specific register at
         a specific point in the code.
        @param addr is the "point" in the code to look for tracked values
        @param resultEncoder will hold the resulting description of registers and values
        @throws IOException for errors in the underlying stream writing the result
        """
        ...

    def getUserOpName(self, index: int) -> unicode:
        """
        Get the name of a user op given its index
        @param index is the given index
        @return the userop name or null
        """
        ...

    def hashCode(self) -> int: ...

    def isNameUsed(self, name: unicode, startId: long, stopId: long) -> bool:
        """
        Decide if a given name is used by any namespace between a starting namespace
         and a stopping namespace.  I.e. check for a name collision along a specific namespace path.
         Currently, Ghidra is inefficient at calculating this perfectly, so this routine calculates
         an approximation that can occasionally indicate a collision when there isn't.
        @param name is the given name to check for collisions
        @param startId is the id specifying the starting namespace
        @param stopId is the id specifying the stopping namespace
        @return true if the name (likely) occurs in one of the namespaces on the path
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setFunction(self, func: ghidra.program.model.listing.Function, entry: ghidra.program.model.address.Address, dbg: ghidra.app.decompiler.DecompileDebug) -> None:
        """
        Establish function and debug context for next decompilation
        @param func is the function to be decompiled
        @param entry is the function's entry address
        @param dbg is the debugging context (or null)
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
    def nativeMessage(self) -> unicode: ...
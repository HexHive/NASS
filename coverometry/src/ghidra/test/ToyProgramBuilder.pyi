from typing import List
import ghidra.program.database
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.util
import java.lang
import java.nio.charset


class ToyProgramBuilder(ghidra.program.database.ProgramBuilder):




    @overload
    def __init__(self, name: unicode, bigEndian: bool):
        """
        Construct toy program builder using toy language "builder" variant.
         This builder will be the program consumer and must be disposed
        @param name program name
        @param bigEndian language endianess
        @throws Exception
        """
        ...

    @overload
    def __init__(self, name: unicode, bigEndian: bool, consumer: object):
        """
        Construct toy program builder using toy language "builder" variant.
         This builder will be the program consumer and must be disposed
        @param name program name
        @param bigEndian language endianess
        @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
        @throws Exception
        """
        ...

    @overload
    def __init__(self, name: unicode, languageName: unicode, consumer: object):
        """
        Construct toy program builder using specified toy language
        @param name program name
        @param languageName toy language ID (note: only builder variant supports all instructions)
        @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
        @throws Exception
        """
        ...

    @overload
    def __init__(self, name: unicode, bigEndian: bool, wordAligned: bool, consumer: object):
        """
        Construct toy program builder using toy language "builder" variant.
         This builder will be the program consumer and must be disposed
        @param name program name
        @param bigEndian language endianess
        @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
        @throws Exception
        """
        ...



    @overload
    def addBytesBadInstruction(self, offset: long) -> None:
        """
        Add BAD instruction (consumes 2-bytes).  Location will not be added to
         defined instruction address list.
        @param offset bad instruction address offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesBadInstruction(self, addr: unicode) -> None:
        """
        Add BAD instruction (consumes 2-bytes).  Location will not be added to
         defined instruction address list.
        @param addr bad instruction address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesBranch(self, offset: long, dest: long) -> None:
        """
        Add branch (consumes 2-bytes)
        @param offset address offset
        @param dest call destination offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesBranch(self, addr: unicode, destAddr: unicode) -> None:
        """
        Add branch (consumes 2-bytes)
        @param addr instruction address offset
        @param destAddr call destination address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesBranchConditional(self, offset: long, dest: long) -> None:
        """
        Add branch (consumes 2-bytes)
        @param offset instruction address offset
        @param dest call destination offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesBranchConditional(self, addr: unicode, destAddr: unicode) -> None:
        """
        Add branch (consumes 2-bytes)
        @param addr instruction address
        @param destAddr call destination address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesBranchWithDelaySlot(self, offset: long, dest: long) -> None:
        """
        Add branch w/ delay slot (consumes 4-bytes)
        @param offset instruction address offset
        @param dest call destination offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesBranchWithDelaySlot(self, addr: unicode, destAddr: unicode) -> None:
        """
        Add branch w/ delay slot (consumes 4-bytes)
        @param addr instruction address
        @param destAddr call destination address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesCall(self, offset: long, dest: long) -> None:
        """
        Add call (consumes 2-bytes)
        @param offset instruction address offset
        @param dest call destination offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesCall(self, addr: unicode, destAddr: unicode) -> None:
        """
        Add call (consumes 2-bytes)
        @param addr instruction address
        @param destAddr call destination address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesCallWithDelaySlot(self, offset: long, dest: long) -> None:
        """
        Add call w/ delayslot (consumes 4-bytes)
        @param offset instruction address offset
        @param dest call destination offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesCallWithDelaySlot(self, addr: unicode, destAddr: unicode) -> None:
        """
        Add call w/ delayslot (consumes 4-bytes)
        @param addr instruction address
        @param destAddr call destination address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesCopInstruction(self, offset: long) -> None:
        """
        Add COP instruction for exercising nfctx context (consumes 2-bytes).  Location will not be added to
         defined instruction address list.
        @param offset instruction address offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesCopInstruction(self, addr: unicode) -> None:
        """
        Add COP instruction for exercising nfctx context (consumes 2-bytes).  Location will not be added to
         defined instruction address list.
        @param addr instruction address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthrough(self, offset: long) -> None:
        """
        Add simple fall-through (consumes 2-bytes)
        @param offset instruction address offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthrough(self, addr: unicode) -> None:
        """
        Add simple fall-through (consumes 2-bytes)
        @param addr instruction address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthroughSetFlowContext(self, offset: long, ctxVal: int) -> None:
        """
        Add simple fall-through which sets flowing context value on next instruction (consumes 2-bytes)
        @param offset instruction address offset
        @param ctxVal context value (0-15)
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthroughSetFlowContext(self, addr: unicode, ctxVal: int) -> None:
        """
        Add simple fall-through which sets flowing context value on next instruction (consumes 2-bytes)
        @param addr instruction address
        @param ctxVal context value (0-15)
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthroughSetNoFlowContext(self, offset: long, ctxVal: int) -> None:
        """
        Add simple fall-through which sets noflow context value on next instruction (consumes 2-bytes)
        @param offset instruction address offset
        @param ctxVal context value (0-15)
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthroughSetNoFlowContext(self, addr: unicode, ctxVal: int) -> None:
        """
        Add simple fall-through which sets noflow context value on next instruction (consumes 2-bytes)
        @param addr instruction address
        @param ctxVal context value (0-15)
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthroughSetNoFlowContext(self, offset: long, ctxVal: int, target: long) -> None:
        """
        Add simple fall-through which sets noflow context value on target address (consumes 2-bytes)
        @param offset instruction address offset
        @param ctxVal context value (0-15)
        @param target context target address offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesFallthroughSetNoFlowContext(self, addr: unicode, ctxVal: int, targetAddr: unicode) -> None:
        """
        Add simple fall-through which sets noflow context value on target address (consumes 2-bytes)
        @param addr instruction address
        @param ctxVal context value (0-15)
        @param targetAddr context target address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesLoad(self, offset: long, srcRegIndex: int, destRegIndex: int) -> None:
        """
        Add load indirect (consumes 2-bytes)
        @param offset instruction address offset
        @param srcRegIndex source register index (contained indirect memory address) (0..15)
        @param destRegIndex destination register index (0..15)
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesLoad(self, addr: unicode, srcRegIndex: int, destRegIndex: int) -> None:
        """
        Add load indirect (consumes 2-bytes)
        @param addr instruction address
        @param srcRegIndex source register index (contained indirect memory address) (0..15)
        @param destRegIndex destination register index (0..15)
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesMoveImmediate(self, offset: long, imm: int) -> None:
        """
        Add move immediate instruction (consumes 2-bytes)
        @param offset instruction offset
        @param imm immediate byte value
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesMoveImmediate(self, addr: unicode, imm: int) -> None:
        """
        Add move immediate instruction (consumes 2-bytes)
        @param addr instruction address
        @param imm immediate byte value
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesNOP(self, offset: long, length: int) -> None:
        """
        Add NOP instruction bytes of specified byte length
        @param offset instruction address offset
        @param length length of NOP instruction in bytes
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesNOP(self, addr: unicode, length: int) -> None:
        """
        Add NOP instruction bytes of specified byte length
        @param addr instruction address
        @param length length of NOP instruction in bytes
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesReturn(self, offset: long) -> None:
        """
        Add terminal/return (consumes 2-bytes)
        @param offset instruction address offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesReturn(self, addr: unicode) -> None:
        """
        Add terminal/return (consumes 2-bytes)
        @param addr instruction address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesSkipConditional(self, offset: long) -> None:
        """
        Add conditional skip (consumes 2-bytes)
        @param offset instruction address offset
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesSkipConditional(self, addr: unicode) -> None:
        """
        Add conditional skip (consumes 2-bytes)
        @param addr instruction address
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesStore(self, offset: long, srcRegIndex: int, destRegIndex: int) -> None:
        """
        Add store indirect (consumes 2-bytes)
        @param offset instruction address offset
        @param srcRegIndex source register index (0..15)
        @param destRegIndex destination register index (contained indirect memory address)  (0..15)
        @throws MemoryAccessException
        """
        ...

    @overload
    def addBytesStore(self, addr: unicode, srcRegIndex: int, destRegIndex: int) -> None:
        """
        Add store indirect (consumes 2-bytes)
        @param addr instruction address
        @param srcRegIndex source register index (0..15)
        @param destRegIndex destination register index (contained indirect memory address)  (0..15)
        @throws MemoryAccessException
        """
        ...

    def addCategory(self, path: ghidra.program.model.data.CategoryPath) -> None: ...

    def addDataType(self, dt: ghidra.program.model.data.DataType) -> None: ...

    def addFunctionVariable(self, f: ghidra.program.model.listing.Function, v: ghidra.program.model.listing.Variable) -> None: ...

    @overload
    def addr(self, offset: long) -> ghidra.program.model.address.Address: ...

    @overload
    def addr(self, addressString: unicode) -> ghidra.program.model.address.Address: ...

    def analyze(self) -> None:
        """
        Perform complete analysis on the built program.
         Limited analysis may already have been performed during disassembly - so it may not
         be necessary to do complete analysis
        """
        ...

    @overload
    def applyDataType(self, addressString: unicode, dt: ghidra.program.model.data.DataType) -> None: ...

    @overload
    def applyDataType(self, addressString: unicode, dt: ghidra.program.model.data.DataType, n: int) -> None:
        """
        Creates a data instance at the specified address, repeated {@code N} times.
        @param addressString address.
        @param dt {@link DataType} to place at address, {@link Dynamic} length datatype not supported.
        @param n repeat count.
        """
        ...

    def applyFixedLengthDataType(self, addressString: unicode, dt: ghidra.program.model.data.DataType, length: int) -> None: ...

    def applyStringDataType(self, addressString: unicode, dt: ghidra.program.model.data.AbstractStringDataType, n: int) -> None:
        """
        Creates a sting data type instance at the specified address, repeated {@code N} times.
        @param addressString address.
        @param dt {@link AbstractStringDataType} string type to place at address.
        @param n repeat count.
        """
        ...

    def bindExternalLibrary(self, libraryName: unicode, pathname: unicode) -> None: ...

    def clearCodeUnits(self, startAddressString: unicode, endAddressString: unicode, clearContext: bool) -> None: ...

    def createBookmark(self, address: unicode, bookmarkType: unicode, category: unicode, comment: unicode) -> ghidra.program.model.listing.Bookmark: ...

    def createCallInstruction(self, address: unicode, callAddress: unicode) -> None: ...

    def createClassNamespace(self, name: unicode, parentNamespace: unicode, type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace: ...

    def createComment(self, address: unicode, comment: unicode, commentType: int) -> None: ...

    def createConditionalJmpInstruction(self, address: unicode, destAddress: unicode) -> None: ...

    @overload
    def createEmptyFunction(self, name: unicode, address: unicode, size: int, returnType: ghidra.program.model.data.DataType, params: List[ghidra.program.model.listing.Parameter]) -> ghidra.program.model.listing.Function: ...

    @overload
    def createEmptyFunction(self, name: unicode, namespace: unicode, address: unicode, bodySize: int, returnType: ghidra.program.model.data.DataType, params: List[ghidra.program.model.listing.Parameter]) -> ghidra.program.model.listing.Function: ...

    @overload
    def createEmptyFunction(self, name: unicode, namespace: unicode, callingConventionName: unicode, address: unicode, size: int, returnType: ghidra.program.model.data.DataType, paramTypes: List[ghidra.program.model.data.DataType]) -> ghidra.program.model.listing.Function: ...

    @overload
    def createEmptyFunction(self, name: unicode, address: unicode, size: int, returnType: ghidra.program.model.data.DataType, varargs: bool, inline: bool, noReturn: bool, params: List[ghidra.program.model.listing.Parameter]) -> ghidra.program.model.listing.Function: ...

    @overload
    def createEmptyFunction(self, name: unicode, namespace: unicode, callingConventionName: unicode, customStorage: bool, address: unicode, bodySize: int, returnType: ghidra.program.model.data.DataType, params: List[ghidra.program.model.listing.Parameter]) -> ghidra.program.model.listing.Function: ...

    def createEncodedString(self, address: unicode, string: unicode, encoding: java.nio.charset.Charset, nullTerminate: bool) -> None: ...

    def createEntryPoint(self, addressString: unicode, name: unicode) -> ghidra.program.model.symbol.Symbol: ...

    def createEquate(self, address: unicode, name: unicode, value: long, opIndex: int) -> ghidra.program.model.symbol.Equate: ...

    @overload
    def createExternalFunction(self, extAddress: unicode, libName: unicode, functionName: unicode) -> ghidra.program.model.symbol.ExternalLocation: ...

    @overload
    def createExternalFunction(self, extAddress: unicode, libName: unicode, functionName: unicode, originalName: unicode) -> ghidra.program.model.symbol.ExternalLocation: ...

    def createExternalLibraries(self, libraryNames: List[unicode]) -> None: ...

    @overload
    def createExternalReference(self, fromAddress: unicode, libraryName: unicode, externalLabel: unicode, opIndex: int) -> None: ...

    @overload
    def createExternalReference(self, fromAddress: unicode, libraryName: unicode, externalLabel: unicode, extAddress: unicode, opIndex: int) -> None: ...

    @overload
    def createExternalReference(self, fromAddress: unicode, libraryName: unicode, externalLabel: unicode, extAddress: unicode, opIndex: int, refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType) -> None: ...

    def createFragment(self, treeName: unicode, modulePath: unicode, fragmentName: unicode, startAddr: unicode, endAddr: unicode) -> None: ...

    def createFunction(self, addressString: unicode) -> ghidra.program.model.listing.Function:
        """
        Creates a function by examining the instructions to find the body.
        @param addressString the address
        @return the function
        """
        ...

    def createFunctionComment(self, entryPointAddress: unicode, comment: unicode) -> None: ...

    def createJmpInstruction(self, address: unicode, destAddress: unicode) -> None: ...

    def createJmpWithDelaySlot(self, address: unicode, destAddress: unicode) -> None: ...

    @overload
    def createLabel(self, addressString: unicode, name: unicode) -> ghidra.program.model.symbol.Symbol: ...

    @overload
    def createLabel(self, addressString: unicode, name: unicode, namespace: unicode) -> ghidra.program.model.symbol.Symbol: ...

    @overload
    def createLibrary(self, libraryName: unicode) -> ghidra.program.model.listing.Library: ...

    @overload
    def createLibrary(self, libraryName: unicode, type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Library: ...

    def createLocalVariable(self, function: ghidra.program.model.listing.Function, name: unicode, dt: ghidra.program.model.data.DataType, stackOffset: int) -> None: ...

    @overload
    def createMemory(self, name: unicode, address: unicode, size: int) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def createMemory(self, name: unicode, address: unicode, size: int, comment: unicode) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def createMemory(self, name: unicode, address: unicode, size: int, comment: unicode, initialValue: int) -> ghidra.program.model.mem.MemoryBlock: ...

    def createMemoryCallReference(self, fromAddress: unicode, toAddress: unicode) -> ghidra.program.model.symbol.Reference: ...

    def createMemoryJumpReference(self, fromAddress: unicode, toAddress: unicode) -> ghidra.program.model.symbol.Reference: ...

    def createMemoryReadReference(self, fromAddress: unicode, toAddress: unicode) -> ghidra.program.model.symbol.Reference: ...

    @overload
    def createMemoryReference(self, fromAddress: unicode, toAddress: unicode, refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Reference: ...

    @overload
    def createMemoryReference(self, fromAddress: unicode, toAddress: unicode, refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType, opIndex: int) -> ghidra.program.model.symbol.Reference: ...

    def createNOPInstruction(self, address: unicode, size: int) -> None: ...

    @overload
    def createNamespace(self, namespace: unicode) -> ghidra.program.model.symbol.Namespace: ...

    @overload
    def createNamespace(self, namespace: unicode, type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace: ...

    @overload
    def createNamespace(self, namespace: unicode, parentNamespace: unicode, type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace: ...

    def createOffsetMemReference(self, fromAddress: unicode, toAddress: unicode, offset: int, refType: ghidra.program.model.symbol.RefType, sourceType: ghidra.program.model.symbol.SourceType, opIndex: int) -> ghidra.program.model.symbol.Reference: ...

    def createOverlayMemory(self, name: unicode, address: unicode, size: int) -> ghidra.program.model.mem.MemoryBlock: ...

    def createProgramTree(self, treeName: unicode) -> None: ...

    @overload
    def createRegisterReference(self, fromAddress: unicode, registerName: unicode, opIndex: int) -> ghidra.program.model.symbol.Reference: ...

    @overload
    def createRegisterReference(self, fromAddress: unicode, refType: ghidra.program.model.symbol.RefType, registerName: unicode, sourceType: ghidra.program.model.symbol.SourceType, opIndex: int) -> ghidra.program.model.symbol.Reference: ...

    def createReturnInstruction(self, address: unicode) -> None: ...

    def createStackReference(self, fromAddress: unicode, refType: ghidra.program.model.symbol.RefType, stackOffset: int, sourceType: ghidra.program.model.symbol.SourceType, opIndex: int) -> ghidra.program.model.symbol.Reference: ...

    @overload
    def createString(self, address: unicode, stringBytes: List[int], charset: java.nio.charset.Charset, dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Data: ...

    @overload
    def createString(self, address: unicode, string: unicode, charset: java.nio.charset.Charset, nullTerminate: bool, dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Data: ...

    def createUninitializedMemory(self, name: unicode, address: unicode, size: int) -> ghidra.program.model.mem.MemoryBlock: ...

    def deleteFunction(self, address: unicode) -> None: ...

    def deleteReference(self, reference: ghidra.program.model.symbol.Reference) -> None: ...

    @overload
    def disassemble(self, set: ghidra.program.model.address.AddressSetView) -> None: ...

    @overload
    def disassemble(self, addressString: unicode, length: int) -> None: ...

    @overload
    def disassemble(self, set: ghidra.program.model.address.AddressSetView, followFlows: bool) -> None: ...

    @overload
    def disassemble(self, addressString: unicode, length: int, followFlows: bool) -> None: ...

    def disassembleArm(self, addressString: unicode, length: int, thumb: bool) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self, offset: long) -> ghidra.program.model.address.Address:
        """
        Get address in default ram space
        @param offset address offset
        @return the address
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec: ...

    def getDefinedInstructionAddress(self) -> List[ghidra.program.model.address.Address]:
        """
        Get locations where instruction bytes have been added
        @return instruction start locations
        """
        ...

    def getLanguage(self) -> ghidra.program.model.lang.Language: ...

    @overload
    def getNamespace(self, namespace: unicode) -> ghidra.program.model.symbol.Namespace: ...

    @overload
    def getNamespace(self, namespace: unicode, address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Namespace: ...

    def getOrCreateModule(self, treeName: unicode, modulePath: unicode) -> ghidra.program.model.listing.ProgramModule: ...

    def getProgram(self) -> ghidra.program.database.ProgramDB:
        """
        Get the constructed program.  If this builder was not constructed with a consumer,
         the caller should dispose the builder after either the program is no longer
         in use, or a new consumer has been added to the program (e.g., program opened
         in a tool or another consumer explicitly added).
        @return constructed program
        """
        ...

    def getRegister(self, regName: unicode) -> ghidra.program.model.lang.Register: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def resetDefinedInstructionAddresses(self) -> None:
        """
        Reset/clear the list of defined instruction addresses
        """
        ...

    def setAnalysisEnabled(self, name: unicode, enabled: bool) -> None: ...

    def setAnalyzed(self) -> None:
        """
        This prevents the 'ask to analyze' dialog from showing when called with {@code true}
        """
        ...

    @overload
    def setBytes(self, address: unicode, byteString: unicode) -> None:
        """
        Sets the bytes starting at {@code address} to the values encoded in {@code byteString}.
         <p>
         See {@link #setBytes(String, byte[], boolean)}.
         <p>
        @param address String containing numeric value, preferably hex encoded: "0x1004000"
        @param byteString String containing 2 digit hex values, separated by ' ' space chars
         or by comma ',' chars: "12 05 ff".  See {@link NumericUtilities#parseHexLong(String)}.
        @throws Exception if there is an exception applying the bytes
        """
        ...

    @overload
    def setBytes(self, stringAddress: unicode, bytes: List[int]) -> None: ...

    @overload
    def setBytes(self, address: unicode, byteString: unicode, disassemble: bool) -> None:
        """
        Sets the bytes starting at {@code address} to the values encoded in {@code byteString}
         and then optionally disassembling.
         <p>
         See {@link #setBytes(String, byte[], boolean)}.
         <p>
        @param address String containing numeric value, preferably hex encoded: "0x1004000"
        @param byteString String containing 2 digit hex values, separated by ' ' space chars
         or by comma ',' chars: "12 05 ff".  See {@link NumericUtilities#parseHexLong(String)}.
        @param disassemble boolean flag.
        @throws Exception if there is an exception applying the bytes
        """
        ...

    @overload
    def setBytes(self, stringAddress: unicode, bytes: List[int], disassemble: bool) -> None:
        """
        Sets the bytes starting at {@code stringAddress} to the byte values in {@code bytes}
         and then optionally disassembling.
         <p>
        @param stringAddress String containing numeric value, preferably hex encoded: "0x1004000"
        @param bytes array of bytes to copy into the memory buffer at the addresss.
        @param disassemble boolean flag.  See {@link #disassemble(String, int)}
        @throws Exception if there is an exception applying the bytes
        """
        ...

    def setChanged(self, changed: bool) -> None: ...

    def setExecute(self, block: ghidra.program.model.mem.MemoryBlock, e: bool) -> None: ...

    def setFallthrough(self, from_: unicode, to: unicode) -> None: ...

    def setIntProperty(self, address: unicode, propertyName: unicode, value: int) -> None: ...

    def setName(self, name: unicode) -> None: ...

    def setObjectProperty(self, address: unicode, propertyName: unicode, value: ghidra.util.Saveable) -> None: ...

    def setProperty(self, name: unicode, value: object) -> None: ...

    def setRead(self, block: ghidra.program.model.mem.MemoryBlock, r: bool) -> None: ...

    def setRecordChanges(self, enabled: bool) -> None: ...

    def setRegisterValue(self, registerName: unicode, startAddress: unicode, endAddress: unicode, value: long) -> None: ...

    def setStringProperty(self, address: unicode, propertyName: unicode, value: unicode) -> None: ...

    def setWrite(self, block: ghidra.program.model.mem.MemoryBlock, w: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def withTransaction(self, r: java.lang.Runnable) -> None: ...

    @property
    def definedInstructionAddress(self) -> List[object]: ...
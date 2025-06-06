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


class ProgramBuilder(object):
    _8051: unicode = u'8051:BE:16:default'
    _AARCH64: unicode = u'AARCH64:LE:64:v8A'
    _ARM: unicode = u'ARM:LE:32:v7'
    _MIPS: unicode = u'MIPS:BE:32:default'
    _MIPS_6432: unicode = u'MIPS:BE:64:64-32addr'
    _PPC_32: unicode = u'PowerPC:BE:32:default'
    _PPC_64: unicode = u'PowerPC:BE:64:default'
    _PPC_6432: unicode = u'PowerPC:BE:64:64-32addr'
    _SPARC64: unicode = u'sparc:BE:64:default'
    _TOY: unicode = u'Toy:BE:32:default'
    _TOY64_BE: unicode = u'Toy:BE:64:default'
    _TOY64_LE: unicode = u'Toy:LE:64:default'
    _TOY_BE: unicode = u'Toy:BE:32:default'
    _TOY_BE_POSITIVE: unicode = u'Toy:BE:32:posStack'
    _TOY_LE: unicode = u'Toy:LE:32:default'
    _TOY_WORDSIZE2_BE: unicode = u'Toy:BE:32:wordSize2'
    _TOY_WORDSIZE2_LE: unicode = u'Toy:LE:32:wordSize2'
    _X64: unicode = u'x86:LE:64:default'
    _X86: unicode = u'x86:LE:32:default'
    _X86_16_REAL_MODE: unicode = u'x86:LE:16:Real Mode'



    @overload
    def __init__(self):
        """
        Construct program builder using the big-endian Toy language and default compiler spec.
         This builder object will be the program consumer and must be disposed to properly
         release the program.
        @throws Exception if there is an exception creating the program
        """
        ...

    @overload
    def __init__(self, name: unicode, languageName: unicode):
        """
        Construct program builder using specified language and default compiler spec.
         This builder object will be the program consumer and must be disposed to properly
         release the program.
        @param name program name
        @param languageName supported language ID (includes all Toy language IDs)
        @throws Exception if there is an exception creating the program
        """
        ...

    @overload
    def __init__(self, name: unicode, language: ghidra.program.model.lang.Language):
        """
        Construct program builder using a full language object rather than a language id string
        @param name program name
        @param language Language object
        @throws Exception if there is an exception creating the program
        """
        ...

    @overload
    def __init__(self, name: unicode, languageName: unicode, consumer: object):
        """
        Construct program builder using specified language and default compiler spec
        @param name program name
        @param languageName supported language ID (includes all Toy language IDs)
        @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
        @throws Exception if there is an exception creating the program
        """
        ...

    @overload
    def __init__(self, name: unicode, languageName: unicode, compilerSpecID: unicode, consumer: object):
        """
        Construct program builder using specified language
        @param name program name
        @param languageName supported language ID (includes all Toy language IDs)
        @param compilerSpecID compiler specification ID (if null default spec will be used)
        @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
        @throws Exception if there is an exception creating the program
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

    def createClassNamespace(self, name: unicode, parentNamespace: unicode, type: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace: ...

    def createComment(self, address: unicode, comment: unicode, commentType: int) -> None: ...

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

    def getClass(self) -> java.lang.Class: ...

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec: ...

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
    def changed(self) -> None: ...  # No getter available.

    @changed.setter
    def changed(self, value: bool) -> None: ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec: ...

    @property
    def language(self) -> ghidra.program.model.lang.Language: ...

    @property
    def name(self) -> None: ...  # No getter available.

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def program(self) -> ghidra.program.database.ProgramDB: ...

    @property
    def recordChanges(self) -> None: ...  # No getter available.

    @recordChanges.setter
    def recordChanges(self, value: bool) -> None: ...
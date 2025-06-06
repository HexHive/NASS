from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import ghidra.trace.util
import ghidra.util
import java.io
import java.lang
import java.nio
import java.util


class TraceInstruction(ghidra.trace.model.listing.TraceCodeUnit, ghidra.program.model.listing.Instruction, object):
    COMMENT_PROPERTY: unicode = u'COMMENT__GHIDRA_'
    DEFINED_DATA_PROPERTY: unicode = u'DEFINED_DATA__GHIDRA_'
    EOL_COMMENT: int = 0
    INSTRUCTION_PROPERTY: unicode = u'INSTRUCTION__GHIDRA_'
    INVALID_DEPTH_CHANGE: int = 16777216
    MAX_LENGTH_OVERRIDE: int = 7
    MNEMONIC: int = -1
    NO_COMMENT: int = -1
    PLATE_COMMENT: int = 3
    POST_COMMENT: int = 2
    PRE_COMMENT: int = 1
    REPEATABLE_COMMENT: int = 4
    SPACE_PROPERTY: unicode = u'Space'







    def addMnemonicReference(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.symbol.RefType, __a2: ghidra.program.model.symbol.SourceType) -> None: ...

    def addOperandReference(self, __a0: int, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.symbol.RefType, __a3: ghidra.program.model.symbol.SourceType) -> None: ...

    def clearFallThroughOverride(self) -> None: ...

    def clearRegister(self, __a0: ghidra.program.model.lang.Register) -> None: ...

    def compareTo(self, __a0: ghidra.program.model.address.Address) -> int: ...

    def contains(self, __a0: ghidra.program.model.address.Address) -> bool: ...

    def delete(self) -> None: ...

    @overload
    @staticmethod
    def dumpContextValue(__a0: ghidra.program.model.lang.RegisterValue, __a1: unicode) -> unicode: ...

    @overload
    @staticmethod
    def dumpContextValue(__a0: ghidra.program.model.lang.RegisterValue, __a1: unicode, __a2: java.lang.StringBuilder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def getAddress(self) -> ghidra.program.model.address.Address: ...

    @overload
    def getAddress(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getAddressString(self, __a0: bool, __a1: bool) -> unicode: ...

    def getBaseContextRegister(self) -> ghidra.program.model.lang.Register: ...

    def getBigInteger(self, __a0: int, __a1: int, __a2: bool) -> long: ...

    def getBounds(self) -> ghidra.trace.model.TraceAddressSnapRange: ...

    def getByte(self, __a0: int) -> int: ...

    @overload
    def getBytes(self) -> List[int]: ...

    @overload
    def getBytes(self, __a0: List[int], __a1: int) -> int: ...

    @overload
    def getBytes(self, __a0: java.nio.ByteBuffer, __a1: int) -> int: ...

    def getBytesInCodeUnit(self, __a0: List[int], __a1: int) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self, __a0: int) -> unicode: ...

    def getCommentAsArray(self, __a0: int) -> List[unicode]: ...

    def getDefaultFallThrough(self) -> ghidra.program.model.address.Address: ...

    def getDefaultFallThroughOffset(self) -> int: ...

    def getDefaultFlows(self) -> List[ghidra.program.model.address.Address]: ...

    def getDefaultOperandRepresentation(self, __a0: int) -> unicode: ...

    def getDefaultOperandRepresentationList(self, __a0: int) -> List[object]: ...

    def getDelaySlotDepth(self) -> int: ...

    def getEndSnap(self) -> long: ...

    def getExternalReference(self, __a0: int) -> ghidra.program.model.symbol.ExternalReference: ...

    def getFallFrom(self) -> ghidra.program.model.address.Address: ...

    def getFallThrough(self) -> ghidra.program.model.address.Address: ...

    def getFlowOverride(self) -> ghidra.program.model.listing.FlowOverride: ...

    def getFlowType(self) -> ghidra.program.model.symbol.FlowType: ...

    def getFlows(self) -> List[ghidra.program.model.address.Address]: ...

    def getGuestDefaultFallThrough(self) -> ghidra.program.model.address.Address: ...

    def getGuestDefaultFlows(self) -> List[ghidra.program.model.address.Address]: ...

    def getInputObjects(self) -> List[object]: ...

    @overload
    def getInputStream(self) -> java.io.InputStream: ...

    @overload
    def getInputStream(self, __a0: int, __a1: int) -> java.io.InputStream: ...

    def getInstructionContext(self) -> ghidra.program.model.lang.InstructionContext: ...

    def getInt(self, __a0: int) -> int: ...

    def getIntProperty(self, __a0: unicode) -> int: ...

    def getLabel(self) -> unicode: ...

    def getLanguage(self) -> ghidra.program.model.lang.Language: ...

    def getLength(self) -> int: ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan: ...

    def getLong(self, __a0: int) -> long: ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address: ...

    def getMemory(self) -> ghidra.program.model.mem.Memory: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address: ...

    def getMnemonicReferences(self) -> List[ghidra.program.model.symbol.Reference]: ...

    def getMnemonicString(self) -> unicode: ...

    def getNext(self) -> ghidra.program.model.listing.Instruction: ...

    def getNumOperands(self) -> int: ...

    def getObjectProperty(self, __a0: unicode) -> ghidra.util.Saveable: ...

    def getOpObjects(self, __a0: int) -> List[object]: ...

    def getOperandRefType(self, __a0: int) -> ghidra.program.model.symbol.RefType: ...

    def getOperandReferences(self, __a0: int) -> List[ghidra.trace.model.symbol.TraceReference]: ...

    def getOperandType(self, __a0: int) -> int: ...

    def getParsedBytes(self) -> List[int]: ...

    def getParsedLength(self) -> int: ...

    @overload
    def getPcode(self) -> List[ghidra.program.model.pcode.PcodeOp]: ...

    @overload
    def getPcode(self, __a0: int) -> List[ghidra.program.model.pcode.PcodeOp]: ...

    @overload
    def getPcode(self, __a0: bool) -> List[ghidra.program.model.pcode.PcodeOp]: ...

    def getPlatform(self) -> ghidra.trace.model.guest.TracePlatform: ...

    def getPrevious(self) -> ghidra.program.model.listing.Instruction: ...

    def getPrimaryReference(self, __a0: int) -> ghidra.program.model.symbol.Reference: ...

    def getPrimarySymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getProperty(self, __a0: unicode, __a1: java.lang.Class) -> object: ...

    def getPrototype(self) -> ghidra.program.model.lang.InstructionPrototype: ...

    def getRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getReferenceIteratorTo(self) -> ghidra.program.model.symbol.ReferenceIterator: ...

    def getReferencesFrom(self) -> List[ghidra.program.model.symbol.Reference]: ...

    @overload
    def getRegister(self, __a0: int) -> ghidra.program.model.lang.Register: ...

    @overload
    def getRegister(self, __a0: unicode) -> ghidra.program.model.lang.Register: ...

    def getRegisterValue(self, __a0: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    def getRegisters(self) -> List[object]: ...

    def getResultObjects(self) -> List[object]: ...

    def getScalar(self, __a0: int) -> ghidra.program.model.scalar.Scalar: ...

    def getSeparator(self, __a0: int) -> unicode: ...

    def getShort(self, __a0: int) -> int: ...

    def getStartSnap(self) -> long: ...

    def getStringProperty(self, __a0: unicode) -> unicode: ...

    def getSymbols(self) -> List[ghidra.program.model.symbol.Symbol]: ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread: ...

    def getTrace(self) -> ghidra.trace.model.Trace: ...

    def getTraceSpace(self) -> ghidra.trace.util.TraceAddressSpace: ...

    def getUnsignedByte(self, __a0: int) -> int: ...

    def getUnsignedInt(self, __a0: int) -> long: ...

    def getUnsignedShort(self, __a0: int) -> int: ...

    def getValue(self, __a0: ghidra.program.model.lang.Register, __a1: bool) -> long: ...

    def getVarLengthInt(self, __a0: int, __a1: int) -> int: ...

    def getVarLengthUnsignedInt(self, __a0: int, __a1: int) -> long: ...

    def getVoidProperty(self, __a0: unicode) -> bool: ...

    def hasFallthrough(self) -> bool: ...

    def hasProperty(self, __a0: unicode) -> bool: ...

    def hasValue(self, __a0: ghidra.program.model.lang.Register) -> bool: ...

    def hashCode(self) -> int: ...

    def isBigEndian(self) -> bool: ...

    def isFallThroughOverridden(self) -> bool: ...

    def isFallthrough(self) -> bool: ...

    def isInDelaySlot(self) -> bool: ...

    def isInitializedMemory(self) -> bool: ...

    def isLengthOverridden(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def propertyNames(self) -> java.util.Iterator: ...

    def removeExternalReference(self, __a0: int) -> None: ...

    def removeMnemonicReference(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def removeOperandReference(self, __a0: int, __a1: ghidra.program.model.address.Address) -> None: ...

    def removeProperty(self, __a0: unicode) -> None: ...

    def setComment(self, __a0: int, __a1: unicode) -> None: ...

    def setCommentAsArray(self, __a0: int, __a1: List[unicode]) -> None: ...

    def setEndSnap(self, __a0: long) -> None: ...

    def setFallThrough(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def setFlowOverride(self, __a0: ghidra.program.model.listing.FlowOverride) -> None: ...

    def setLengthOverride(self, __a0: int) -> None: ...

    def setPrimaryMemoryReference(self, __a0: ghidra.program.model.symbol.Reference) -> None: ...

    @overload
    def setProperty(self, __a0: unicode) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: int) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: unicode) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: ghidra.util.Saveable) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: java.lang.Class, __a2: object) -> None: ...

    def setRegisterReference(self, __a0: int, __a1: ghidra.program.model.lang.Register, __a2: ghidra.program.model.symbol.SourceType, __a3: ghidra.program.model.symbol.RefType) -> None: ...

    def setRegisterValue(self, __a0: ghidra.program.model.lang.RegisterValue) -> None: ...

    def setStackReference(self, __a0: int, __a1: int, __a2: ghidra.program.model.symbol.SourceType, __a3: ghidra.program.model.symbol.RefType) -> None: ...

    def setTypedProperty(self, __a0: unicode, __a1: object) -> None: ...

    def setValue(self, __a0: ghidra.program.model.lang.Register, __a1: long) -> None: ...

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
    def baseContextRegister(self) -> ghidra.program.model.lang.Register: ...

    @property
    def bigEndian(self) -> bool: ...

    @property
    def bounds(self) -> ghidra.trace.model.TraceAddressSnapRange: ...

    @property
    def bytes(self) -> List[int]: ...

    @property
    def defaultFallThrough(self) -> ghidra.program.model.address.Address: ...

    @property
    def defaultFallThroughOffset(self) -> int: ...

    @property
    def defaultFlows(self) -> List[ghidra.program.model.address.Address]: ...

    @property
    def delaySlotDepth(self) -> int: ...

    @property
    def endSnap(self) -> long: ...

    @endSnap.setter
    def endSnap(self, value: long) -> None: ...

    @property
    def fallFrom(self) -> ghidra.program.model.address.Address: ...

    @property
    def fallThrough(self) -> ghidra.program.model.address.Address: ...

    @fallThrough.setter
    def fallThrough(self, value: ghidra.program.model.address.Address) -> None: ...

    @property
    def fallThroughOverridden(self) -> bool: ...

    @property
    def fallthrough(self) -> bool: ...

    @property
    def flowOverride(self) -> ghidra.program.model.listing.FlowOverride: ...

    @flowOverride.setter
    def flowOverride(self, value: ghidra.program.model.listing.FlowOverride) -> None: ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType: ...

    @property
    def flows(self) -> List[ghidra.program.model.address.Address]: ...

    @property
    def guestDefaultFallThrough(self) -> ghidra.program.model.address.Address: ...

    @property
    def guestDefaultFlows(self) -> List[ghidra.program.model.address.Address]: ...

    @property
    def inDelaySlot(self) -> bool: ...

    @property
    def initializedMemory(self) -> bool: ...

    @property
    def inputObjects(self) -> List[object]: ...

    @property
    def inputStream(self) -> java.io.InputStream: ...

    @property
    def instructionContext(self) -> ghidra.program.model.lang.InstructionContext: ...

    @property
    def label(self) -> unicode: ...

    @property
    def language(self) -> ghidra.program.model.lang.Language: ...

    @property
    def length(self) -> int: ...

    @property
    def lengthOverridden(self) -> bool: ...

    @property
    def lengthOverride(self) -> None: ...  # No getter available.

    @lengthOverride.setter
    def lengthOverride(self, value: int) -> None: ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan: ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def memory(self) -> ghidra.program.model.mem.Memory: ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def mnemonicReferences(self) -> List[ghidra.trace.model.symbol.TraceReference]: ...

    @property
    def mnemonicString(self) -> unicode: ...

    @property
    def next(self) -> ghidra.trace.model.listing.TraceInstruction: ...

    @property
    def numOperands(self) -> int: ...

    @property
    def parsedBytes(self) -> List[int]: ...

    @property
    def parsedLength(self) -> int: ...

    @property
    def pcode(self) -> List[ghidra.program.model.pcode.PcodeOp]: ...

    @property
    def platform(self) -> ghidra.trace.model.guest.TracePlatform: ...

    @property
    def previous(self) -> ghidra.trace.model.listing.TraceInstruction: ...

    @property
    def primaryMemoryReference(self) -> None: ...  # No getter available.

    @primaryMemoryReference.setter
    def primaryMemoryReference(self, value: ghidra.program.model.symbol.Reference) -> None: ...

    @property
    def primarySymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    @property
    def program(self) -> ghidra.trace.model.program.TraceProgramView: ...

    @property
    def property(self) -> None: ...  # No getter available.

    @property.setter
    def property(self, value: unicode) -> None: ...

    @property
    def prototype(self) -> ghidra.program.model.lang.InstructionPrototype: ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def referenceIteratorTo(self) -> ghidra.program.model.symbol.ReferenceIterator: ...

    @property
    def referencesFrom(self) -> List[ghidra.trace.model.symbol.TraceReference]: ...

    @property
    def registerValue(self) -> None: ...  # No getter available.

    @registerValue.setter
    def registerValue(self, value: ghidra.program.model.lang.RegisterValue) -> None: ...

    @property
    def registers(self) -> List[object]: ...

    @property
    def resultObjects(self) -> List[object]: ...

    @property
    def startSnap(self) -> long: ...

    @property
    def symbols(self) -> List[ghidra.program.model.symbol.Symbol]: ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread: ...

    @property
    def trace(self) -> ghidra.trace.model.Trace: ...

    @property
    def traceSpace(self) -> ghidra.trace.util.TraceAddressSpace: ...
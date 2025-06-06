import ghidra.program.model.address
import ghidra.program.model.symbol
import java.lang


class EntryPointReference(ghidra.program.model.symbol.Reference, object):
    """
    Reference object for entry points
    """

    MNEMONIC: int = -1
    OTHER: int = -2







    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFromAddress(self) -> ghidra.program.model.address.Address: ...

    def getOperandIndex(self) -> int: ...

    def getReferenceType(self) -> ghidra.program.model.symbol.RefType: ...

    def getSource(self) -> ghidra.program.model.symbol.SourceType: ...

    def getSymbolID(self) -> long: ...

    def getToAddress(self) -> ghidra.program.model.address.Address: ...

    def hashCode(self) -> int: ...

    def isEntryPointReference(self) -> bool: ...

    def isExternalReference(self) -> bool: ...

    def isMemoryReference(self) -> bool: ...

    def isMnemonicReference(self) -> bool: ...

    def isOffsetReference(self) -> bool: ...

    def isOperandReference(self) -> bool: ...

    def isPrimary(self) -> bool: ...

    def isRegisterReference(self) -> bool: ...

    def isShiftedReference(self) -> bool: ...

    def isStackReference(self) -> bool: ...

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
    def entryPointReference(self) -> bool: ...

    @property
    def externalReference(self) -> bool: ...

    @property
    def fromAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def memoryReference(self) -> bool: ...

    @property
    def mnemonicReference(self) -> bool: ...

    @property
    def offsetReference(self) -> bool: ...

    @property
    def operandIndex(self) -> int: ...

    @property
    def operandReference(self) -> bool: ...

    @property
    def primary(self) -> bool: ...

    @property
    def referenceType(self) -> ghidra.program.model.symbol.RefType: ...

    @property
    def registerReference(self) -> bool: ...

    @property
    def shiftedReference(self) -> bool: ...

    @property
    def source(self) -> ghidra.program.model.symbol.SourceType: ...

    @property
    def stackReference(self) -> bool: ...

    @property
    def symbolID(self) -> long: ...

    @property
    def toAddress(self) -> ghidra.program.model.address.Address: ...
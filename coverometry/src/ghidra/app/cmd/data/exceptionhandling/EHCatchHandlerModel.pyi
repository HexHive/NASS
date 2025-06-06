import ghidra.app.cmd.data
import ghidra.app.cmd.data.exceptionhandling
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.scalar
import java.lang


class EHCatchHandlerModel(ghidra.app.cmd.data.AbstractCreateDataTypeModel):
    DATA_TYPE_NAME: unicode = u'HandlerType'



    def __init__(self, __a0: ghidra.program.model.listing.Program, __a1: int, __a2: ghidra.program.model.address.Address, __a3: ghidra.app.util.datatype.microsoft.DataValidationOptions): ...



    def checkAgainstMaxCount(self, __a0: unicode, __a1: int, __a2: int) -> None: ...

    def checkEntryCount(self, __a0: unicode, __a1: int, __a2: int) -> None: ...

    def checkNonNegative(self, __a0: unicode, __a1: int) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getCatchHandlerAddress(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getCatchHandlerName(self, __a0: int) -> unicode: ...

    def getCatchObjectDisplacement(self, __a0: int) -> ghidra.program.model.scalar.Scalar: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentAddressOfCatchHandlerAddress(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getComponentAddressOfTypeDescriptorAddress(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getCount(self) -> int: ...

    @overload
    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    @overload
    @staticmethod
    def getDataType(__a0: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType: ...

    def getFunctionFrameAddressDisplacement(self, __a0: int) -> ghidra.program.model.scalar.Scalar: ...

    def getModifiers(self, __a0: int) -> ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerTypeModifier: ...

    def getName(self) -> unicode: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getTypeDescriptorAddress(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getTypeDescriptorModel(self, __a0: int) -> ghidra.app.cmd.data.TypeDescriptorModel: ...

    def hashCode(self) -> int: ...

    def isBlockedByInstructions(self) -> bool: ...

    def isDataTypeAlreadyBasedOnCount(self) -> bool: ...

    def isLoadedAndInitializedAddress(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def validate(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def name(self) -> unicode: ...
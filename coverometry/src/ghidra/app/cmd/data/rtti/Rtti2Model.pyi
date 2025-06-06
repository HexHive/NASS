from typing import List
import ghidra.app.cmd.data
import ghidra.app.cmd.data.rtti
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class Rtti2Model(ghidra.app.cmd.data.rtti.AbstractCreateRttiDataModel):
    DATA_TYPE_NAME: unicode = u'RTTIBaseClassArray'



    def __init__(self, __a0: ghidra.program.model.listing.Program, __a1: int, __a2: ghidra.program.model.address.Address, __a3: ghidra.app.util.datatype.microsoft.DataValidationOptions): ...



    def checkAgainstMaxCount(self, __a0: unicode, __a1: int, __a2: int) -> None: ...

    def checkEntryCount(self, __a0: unicode, __a1: int, __a2: int) -> None: ...

    def checkNonNegative(self, __a0: unicode, __a1: int) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getBaseClassTypes(self) -> List[object]: ...

    def getClass(self) -> java.lang.Class: ...

    def getCount(self) -> int: ...

    @overload
    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    @overload
    def getDataType(self, __a0: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType: ...

    @staticmethod
    def getIndividualEntryDataType(__a0: ghidra.program.model.listing.Program, __a1: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType: ...

    def getName(self) -> unicode: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getRtti0Model(self) -> ghidra.app.cmd.data.TypeDescriptorModel: ...

    def getRtti1Address(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getRtti1Model(self, __a0: int) -> ghidra.app.cmd.data.rtti.Rtti1Model: ...

    def hashCode(self) -> int: ...

    def isBlockedByInstructions(self) -> bool: ...

    def isDataTypeAlreadyBasedOnCount(self) -> bool: ...

    def isLoadedAndInitializedAddress(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def refersToRtti0(self, __a0: ghidra.program.model.address.Address) -> bool: ...

    def toString(self) -> unicode: ...

    def validate(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def baseClassTypes(self) -> List[object]: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def name(self) -> unicode: ...

    @property
    def rtti0Model(self) -> ghidra.app.cmd.data.TypeDescriptorModel: ...
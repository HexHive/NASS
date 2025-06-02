from typing import List
import ghidra.app.util.bin.format.dwarf4
import ghidra.app.util.bin.format.dwarf4.next
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang


class DWARFVariable(object):
    """
    Represents a function parameter, local variable, or global variable.
    """

    isExternal: bool
    isOutputParameter: bool
    isThis: bool
    lexicalOffset: long
    name: ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo
    sourceInfo: ghidra.app.util.bin.format.dwarf4.next.DWARFSourceInfo
    type: ghidra.program.model.data.DataType







    def addRamStorage(self, offset: long) -> None: ...

    def addRegisterStorage(self, __a0: List[object]) -> None: ...

    def addStackStorage(self, offset: long, length: int) -> None: ...

    def appendComment(self, prefix: unicode, comment: unicode, sep: unicode) -> None: ...

    def asLocalVariable(self) -> ghidra.program.model.listing.Variable: ...

    def asParameter(self, includeStorageDetail: bool, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.Parameter: ...

    def asParameterDef(self) -> ghidra.program.model.data.ParameterDefinition: ...

    def asReturnParameter(self, includeStorageDetail: bool) -> ghidra.program.model.listing.Parameter: ...

    def clearStorage(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromDataType(dfunc: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction, dt: ghidra.program.model.data.DataType) -> ghidra.app.util.bin.format.dwarf4.next.DWARFVariable:
        """
        Creates an unnamed, storage-less {@link DWARFVariable} from a DataType.
        @param dt {@link DataType} of the variable
        @return new {@link DWARFVariable}, never null
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclInfoString(self) -> unicode: ...

    def getRamAddress(self) -> ghidra.program.model.address.Address:
        """
        If this is a static/global variable, stored at a ram address, return it's
         ram address.
        @return address of where this variable is stored, null if not ram address
        """
        ...

    def getStackOffset(self) -> long:
        """
        If this is a stack variable, return its stack offset.
        @return its stack offset
        """
        ...

    def getStorageSize(self) -> int: ...

    def getToolTip(self) -> unicode: ...

    def getVariableStorage(self) -> ghidra.program.model.listing.VariableStorage: ...

    def getVarnodes(self) -> List[ghidra.program.model.pcode.Varnode]: ...

    def hashCode(self) -> int: ...

    def isEmptyArray(self) -> bool: ...

    def isLocationValidOnEntry(self) -> bool: ...

    def isMissingStorage(self) -> bool: ...

    def isRamStorage(self) -> bool:
        """
        @return true if this variable's storage is in ram
        """
        ...

    def isStackStorage(self) -> bool:
        """
        @return true if this variable is stored on the stack
        """
        ...

    def isVoidType(self) -> bool: ...

    def isZeroByte(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def readGlobalVariable(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> ghidra.app.util.bin.format.dwarf4.next.DWARFVariable:
        """
        Reads a static/global variable.
        @param diea {@link DIEAggregate} DW_TAG_variable
        @return new {@link DWARFVariable} that represents the global variable, or
         <strong>null</strong> if error reading storage info
        """
        ...

    @staticmethod
    def readLocalVariable(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate, dfunc: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction, offsetFromFuncStart: long) -> ghidra.app.util.bin.format.dwarf4.next.DWARFVariable:
        """
        Reads a local variable.
        @param diea {@link DIEAggregate} DW_TAG_variable
        @param dfunc {@link DWARFFunction} that this local var belongs to
        @return new DWARFVariable that represents a local var, or <strong>null</strong> if 
         error reading storage info
        """
        ...

    @staticmethod
    def readParameter(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate, dfunc: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction, paramOrdinal: int) -> ghidra.app.util.bin.format.dwarf4.next.DWARFVariable:
        """
        Reads a parameter.
        @param diea {@link DIEAggregate} DW_TAG_formal_parameter
        @param dfunc {@link DWARFFunction} that this parameter is attached to
        @param paramOrdinal
        @return new parameter, never null, possibly without storage info
        @throws IOException if error
        """
        ...

    def setRamStorage(self, offset: long) -> None:
        """
        Assign storage for this variable in a ram data location.
        @param offset address offset
        """
        ...

    def setRegisterStorage(self, __a0: List[object]) -> None: ...

    def setStackStorage(self, offset: long) -> None:
        """
        Assign storage for this variable at a stack offset.
        @param offset stack offset
        """
        ...

    def setVarnodes(self, __a0: List[object]) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def declInfoString(self) -> unicode: ...

    @property
    def emptyArray(self) -> bool: ...

    @property
    def locationValidOnEntry(self) -> bool: ...

    @property
    def missingStorage(self) -> bool: ...

    @property
    def ramAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def ramStorage(self) -> bool: ...

    @property
    def registerStorage(self) -> None: ...  # No getter available.

    @registerStorage.setter
    def registerStorage(self, value: List[object]) -> None: ...

    @property
    def stackOffset(self) -> long: ...

    @property
    def stackStorage(self) -> bool: ...

    @property
    def storageSize(self) -> int: ...

    @property
    def toolTip(self) -> unicode: ...

    @property
    def variableStorage(self) -> ghidra.program.model.listing.VariableStorage: ...

    @property
    def varnodes(self) -> List[object]: ...

    @varnodes.setter
    def varnodes(self, value: List[object]) -> None: ...

    @property
    def voidType(self) -> bool: ...

    @property
    def zeroByte(self) -> bool: ...
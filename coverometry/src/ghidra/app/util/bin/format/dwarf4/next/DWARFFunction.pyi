from typing import List
import ghidra.app.util.bin.format.dwarf4
import ghidra.app.util.bin.format.dwarf4.next
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang
import java.util


class DWARFFunction(object):
    """
    Represents a function that was read from DWARF information.
    """

    address: ghidra.program.model.address.Address
    callingConvention: ghidra.program.model.data.GenericCallingConvention
    diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate
    frameBase: long
    highAddress: ghidra.program.model.address.Address
    isExternal: bool
    localVarErrors: bool
    localVars: List[object]
    name: ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo
    namespace: ghidra.program.model.symbol.Namespace
    noReturn: bool
    params: List[object]
    prototypeModel: ghidra.program.model.lang.PrototypeModel
    retval: ghidra.app.util.bin.format.dwarf4.next.DWARFVariable
    signatureCommitMode: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode
    sourceInfo: ghidra.app.util.bin.format.dwarf4.next.DWARFSourceInfo
    varArg: bool




    class CommitMode(java.lang.Enum):
        FORMAL: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode = FORMAL
        SKIP: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode = SKIP
        STORAGE: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode = STORAGE







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def asFuncDef(self) -> ghidra.program.model.data.FunctionDefinition:
        """
        Returns a {@link FunctionDefinition} that reflects this function's information.
        @return {@link FunctionDefinition} that reflects this function's information
        """
        ...

    def commitLocalVariable(self, dvar: ghidra.app.util.bin.format.dwarf4.next.DWARFVariable, gfunc: ghidra.program.model.listing.Function) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAllLocalVariableNames(self) -> List[unicode]: ...

    def getAllParamNames(self) -> List[unicode]: ...

    def getCallingConventionName(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getExistingLocalVariableNames(self, gfunc: ghidra.program.model.listing.Function) -> List[unicode]: ...

    def getLocalVarByOffset(self, offset: long) -> ghidra.app.util.bin.format.dwarf4.next.DWARFVariable:
        """
        Returns the DWARFVariable that starts at the specified stack offset.
        @param offset stack offset
        @return local variable that starts at offset, or null if not present
        """
        ...

    def getNonParamSymbolNames(self, gfunc: ghidra.program.model.listing.Function) -> List[unicode]: ...

    def getParameters(self, includeStorageDetail: bool) -> List[ghidra.program.model.listing.Parameter]:
        """
        Returns this function's parameters as a list of {@link Parameter} instances.
        @param includeStorageDetail boolean flag, if true storage information will be included, if
         false, VariableStorage.UNASSIGNED_STORAGE will be used
        @return list of Parameters
        @throws InvalidInputException
        """
        ...

    def getProgram(self) -> ghidra.app.util.bin.format.dwarf4.next.DWARFProgram: ...

    def getRange(self) -> ghidra.app.util.bin.format.dwarf4.DWARFRange: ...

    def hasConflictWithExistingLocalVariableStorage(self, dvar: ghidra.app.util.bin.format.dwarf4.next.DWARFVariable, gfunc: ghidra.program.model.listing.Function) -> bool: ...

    def hasConflictWithParamStorage(self, dvar: ghidra.app.util.bin.format.dwarf4.next.DWARFVariable) -> bool: ...

    def hashCode(self) -> int: ...

    def isInLocalVarStorageArea(self, offset: long) -> bool:
        """
        Returns true if the specified stack offset is within the function's local variable
         storage area.
        @param offset stack offset to test
        @return true if stack offset is within this function's local variable area
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> ghidra.app.util.bin.format.dwarf4.next.DWARFFunction:
        """
        Create a function instance from the information found in the specified DIEA.
        @param diea DW_TAG_subprogram {@link DIEAggregate}
        @return new {@link DWARFFunction}, or null if invalid DWARF information
        @throws IOException if error accessing attribute values
        @throws DWARFExpressionException if error accessing attribute values
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
    def allLocalVariableNames(self) -> List[object]: ...

    @property
    def allParamNames(self) -> List[object]: ...

    @property
    def callingConventionName(self) -> unicode: ...

    @property
    def program(self) -> ghidra.app.util.bin.format.dwarf4.next.DWARFProgram: ...

    @property
    def range(self) -> ghidra.app.util.bin.format.dwarf4.DWARFRange: ...
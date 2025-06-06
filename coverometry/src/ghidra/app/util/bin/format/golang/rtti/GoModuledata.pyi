from typing import Iterator
from typing import List
import ghidra.app.util.bin.format.golang.rtti
import ghidra.app.util.bin.format.golang.rtti.types
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.address
import java.lang


class GoModuledata(object, ghidra.app.util.bin.format.golang.structmapping.StructureMarkup):
    """
    Represents a golang moduledata structure, which contains a lot of invaluable bootstrapping
     data for RTTI and function data.
    """





    def __init__(self): ...



    def additionalMarkup(self, session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> None: ...

    def containsFuncDataInstance(self, offset: long) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getAllFunctionData(self) -> List[ghidra.app.util.bin.format.golang.rtti.GoFuncData]: ...

    def getClass(self) -> java.lang.Class: ...

    def getExternalInstancesToMarkup(self) -> List[object]: ...

    def getFuncDataInstance(self, offset: long) -> ghidra.app.util.bin.format.golang.rtti.GoFuncData: ...

    def getFuncnametab(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice: ...

    def getFunctabEntriesSlice(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice:
        """
        Returns an artificial slice of the functab entries that are valid.
        @return artificial slice of the functab entries that are valid
        """
        ...

    def getItabs(self) -> List[ghidra.app.util.bin.format.golang.rtti.GoItab]: ...

    def getPcHeader(self) -> ghidra.app.util.bin.format.golang.rtti.GoPcHeader: ...

    def getStructureContext(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureContext: ...

    def getStructureLabel(self) -> unicode: ...

    def getStructureName(self) -> unicode: ...

    def getText(self) -> ghidra.program.model.address.Address: ...

    def getTypeList(self) -> List[ghidra.program.model.address.Address]: ...

    def getTypesEndOffset(self) -> long: ...

    def getTypesOffset(self) -> long: ...

    def hashCode(self) -> int: ...

    def isValid(self) -> bool: ...

    def iterateTypes(self) -> Iterator[ghidra.app.util.bin.format.golang.rtti.types.GoType]: ...

    def matchesPclntab(self, pclntab: ghidra.app.util.bin.format.golang.rtti.GoPcHeader) -> bool:
        """
        Compares the data in this structure to fields in a GoPcHeader and returns true if they
         match.
        @param pclntab GoPcHeader instance
        @return boolean true if match, false if no match
        """
        ...

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
    def allFunctionData(self) -> List[object]: ...

    @property
    def externalInstancesToMarkup(self) -> List[object]: ...

    @property
    def funcnametab(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice: ...

    @property
    def functabEntriesSlice(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice: ...

    @property
    def itabs(self) -> List[object]: ...

    @property
    def pcHeader(self) -> ghidra.app.util.bin.format.golang.rtti.GoPcHeader: ...

    @property
    def structureContext(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureContext: ...

    @property
    def structureLabel(self) -> unicode: ...

    @property
    def structureName(self) -> unicode: ...

    @property
    def text(self) -> ghidra.program.model.address.Address: ...

    @property
    def typeList(self) -> List[object]: ...

    @property
    def typesEndOffset(self) -> long: ...

    @property
    def typesOffset(self) -> long: ...

    @property
    def valid(self) -> bool: ...
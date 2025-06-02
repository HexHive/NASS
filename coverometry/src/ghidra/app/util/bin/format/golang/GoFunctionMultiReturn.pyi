from typing import List
import ghidra.app.util.bin.format.golang
import ghidra.program.model.data
import java.lang


class GoFunctionMultiReturn(object):
    """
    Handles creating a Ghidra structure to represent multiple return values returned from a golang
     function.
 
     Assigning custom storage for the return value is complicated by:
 
      golang storage allocations depend on the formal ordering of the return values
     	stack storage must be last in a list of varnodes
     	the decompiler maps a structure's contents to the list of varnodes in an endian-dependent
     	manner.
 
     To meet these complications, the structure's layout is modified to put all items that were
     marked as being stack parameters to either the front or back of the structure.
 
     To allow this artificial structure to adjusted by the user and reused at some later time
     to re-calculate the correct storage, the items in the structure are tagged with the original
     ordinal of that item as a text comment of each structure field, so that the correct ordering
     of items can be re-created when needed.
 
     If the structure layout is modified to conform to an arch's requirements, the structure's
     name will be modified to include that arch's description at the end (eg. "_x86_64")
    """

    MULTIVALUE_RETURNTYPE_SUFFIX: unicode = u'_multivalue_return_type'



    @overload
    def __init__(self, struct: ghidra.program.model.data.Structure, dtm: ghidra.program.model.data.DataTypeManager, storageAllocator: ghidra.app.util.bin.format.golang.GoParamStorageAllocator): ...

    @overload
    def __init__(self, __a0: List[object], __a1: ghidra.app.util.bin.format.dwarf4.next.DWARFFunction, __a2: ghidra.program.model.data.DataTypeManager, __a3: ghidra.app.util.bin.format.golang.GoParamStorageAllocator): ...

    @overload
    def __init__(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode, __a2: List[object], __a3: ghidra.program.model.data.DataTypeManager, __a4: ghidra.app.util.bin.format.golang.GoParamStorageAllocator): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromStructure(dt: ghidra.program.model.data.DataType, dtm: ghidra.program.model.data.DataTypeManager, storageAllocator: ghidra.app.util.bin.format.golang.GoParamStorageAllocator) -> ghidra.app.util.bin.format.golang.GoFunctionMultiReturn: ...

    def getClass(self) -> java.lang.Class: ...

    def getNormalStorageComponents(self) -> List[ghidra.program.model.data.DataTypeComponent]: ...

    def getStackStorageComponents(self) -> List[ghidra.program.model.data.DataTypeComponent]: ...

    def getStruct(self) -> ghidra.program.model.data.Structure: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isMultiReturnDataType(dt: ghidra.program.model.data.DataType) -> bool: ...

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
    def normalStorageComponents(self) -> List[object]: ...

    @property
    def stackStorageComponents(self) -> List[object]: ...

    @property
    def struct(self) -> ghidra.program.model.data.Structure: ...
from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.lang.ParamList
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.xml
import java.lang
import java.util


class ParamListStandardOut(ghidra.program.model.lang.ParamListRegisterOut):
    """
    A list of resources describing possible storage locations for a function's return value,
     and a strategy for selecting a storage location based on data-types in a function signature.
 
     Similar to the parent class, when assigning storage, the first entry that matches the data-type
     is chosen.  But if this instance fails to find a match (because the return value data-type is too
     big) the data-type is converted to a pointer and storage is assigned based on that pointer.
     Additionally, if configured, this instance will signal that a hidden input parameter is required
     to fully model where the large return value is stored.
 
     The resource list is checked to ensure entries are distinguishable.
    """





    def __init__(self): ...



    def assignMap(self, __a0: ghidra.program.model.listing.Program, __a1: List[ghidra.program.model.data.DataType], __a2: java.util.ArrayList, __a3: bool) -> None: ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder, isInput: bool) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPotentialRegisterStorage(self, prog: ghidra.program.model.listing.Program) -> List[ghidra.program.model.listing.VariableStorage]: ...

    def getStackParameterAlignment(self) -> int: ...

    def getStackParameterOffset(self) -> long: ...

    def hashCode(self) -> int: ...

    def isEquivalent(self, obj: ghidra.program.model.lang.ParamList) -> bool: ...

    def isThisBeforeRetPointer(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def possibleParamWithSlot(self, loc: ghidra.program.model.address.Address, size: int, res: ghidra.program.model.lang.ParamList.WithSlotRec) -> bool: ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, cspec: ghidra.program.model.lang.CompilerSpec) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


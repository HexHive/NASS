from typing import List
import ghidra.app.util.bin.format.golang.rtti
import ghidra.app.util.bin.format.golang.rtti.types
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.data
import java.lang
import java.util


class GoArrayType(ghidra.app.util.bin.format.golang.rtti.types.GoType):




    def __init__(self): ...



    def additionalMarkup(self, session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> None: ...

    def discoverGoTypes(self, discoveredTypes: java.util.Set) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDebugId(self) -> unicode: ...

    def getElement(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    def getEndOfTypeInfo(self) -> long:
        """
        Returns the location of where this type object, and any known associated optional
         structures ends.
        @return index location of end of this type object
        @throws IOException if error reading
        """
        ...

    def getExternalInstancesToMarkup(self) -> List[object]: ...

    def getMethodListString(self) -> unicode: ...

    def getNameString(self) -> unicode: ...

    def getSliceType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    @staticmethod
    def getSpecializedTypeClass(programContext: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper, offset: long) -> java.lang.Class:
        """
        Returns the specific GoType derived class that will handle the go type located at the
         specified offset.
        @param programContext program-level mapper context
        @param offset absolute location of go type struct
        @return GoType class that will best handle the type struct
        @throws IOException if error reading
        """
        ...

    def getStructureContext(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureContext: ...

    def getStructureLabel(self) -> unicode: ...

    def getStructureName(self) -> unicode: ...

    def getUncommonType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoUncommonType: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def recoverDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def element(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    @property
    def sliceType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...
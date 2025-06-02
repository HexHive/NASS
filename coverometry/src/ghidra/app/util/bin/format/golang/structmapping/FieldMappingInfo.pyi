from typing import List
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.data
import java.lang
import java.lang.reflect


class FieldMappingInfo(object):
    """
    Immutable information needed to deserialize a field in a structure mapped class.
    """









    def addCommentMarkupFuncs(self) -> None: ...

    def addMarkupFunc(self, func: ghidra.app.util.bin.format.golang.structmapping.FieldMarkupFunction) -> None: ...

    def addMarkupNestedFuncs(self) -> None: ...

    def addMarkupReferenceFunc(self) -> None: ...

    def assignField(self, fieldContext: ghidra.app.util.bin.format.golang.structmapping.FieldContext, value: object) -> None: ...

    @staticmethod
    def createEarlyBinding(field: java.lang.reflect.Field, dtc: ghidra.program.model.data.DataTypeComponent, signedness: ghidra.app.util.bin.format.golang.structmapping.Signedness, length: int) -> ghidra.app.util.bin.format.golang.structmapping.FieldMappingInfo:
        """
        Creates a FieldMappingInfo instance, used when the structure is not variable length.
        @param <T> structure mapped class type
        @param field java field
        @param dtc Ghidra structure field
        @param signedness {@link Signedness} enum
        @param length override of structure field, or -1
        @return new {@link FieldMappingInfo} instance
        """
        ...

    @staticmethod
    def createLateBinding(field: java.lang.reflect.Field, fieldName: unicode, signedness: ghidra.app.util.bin.format.golang.structmapping.Signedness, length: int) -> ghidra.app.util.bin.format.golang.structmapping.FieldMappingInfo:
        """
        Creates a FieldMappingInfo instance, used when the structure is variable length and there is
         no pre-defined Ghidra Structure data type.
        @param <T> structure mapped class type
        @param field java field
        @param fieldName name of Ghidra structure field
        @param signedness {@link Signedness} enum
        @param length override of structure field, or -1
        @return new {@link FieldMappingInfo} instance
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def findDtc(self, struct: ghidra.program.model.data.Structure) -> ghidra.program.model.data.DataTypeComponent: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getDtc(self) -> ghidra.program.model.data.DataTypeComponent: ...

    @overload
    def getDtc(self, structure: ghidra.program.model.data.Structure) -> ghidra.program.model.data.DataTypeComponent: ...

    def getField(self) -> java.lang.reflect.Field: ...

    def getFieldName(self) -> unicode: ...

    def getLength(self) -> int: ...

    def getMarkupFuncs(self) -> List[ghidra.app.util.bin.format.golang.structmapping.FieldMarkupFunction]: ...

    def getReaderFunc(self) -> ghidra.app.util.bin.format.golang.structmapping.FieldReadFunction: ...

    def getSignedness(self) -> ghidra.app.util.bin.format.golang.structmapping.Signedness: ...

    def getValue(self, structInstance: object, expectedType: java.lang.Class) -> R: ...

    def hashCode(self) -> int: ...

    def isStructureMappedType(self) -> bool: ...

    def isUnsigned(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setFieldValueDeserializationInfo(self, fieldReadValueClass: java.lang.Class, structTargetClass: java.lang.Class, setterNameOverride: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def dtc(self) -> ghidra.program.model.data.DataTypeComponent: ...

    @property
    def field(self) -> java.lang.reflect.Field: ...

    @property
    def fieldName(self) -> unicode: ...

    @property
    def length(self) -> int: ...

    @property
    def markupFuncs(self) -> List[object]: ...

    @property
    def readerFunc(self) -> ghidra.app.util.bin.format.golang.structmapping.FieldReadFunction: ...

    @property
    def signedness(self) -> ghidra.app.util.bin.format.golang.structmapping.Signedness: ...

    @property
    def structureMappedType(self) -> bool: ...

    @property
    def unsigned(self) -> bool: ...
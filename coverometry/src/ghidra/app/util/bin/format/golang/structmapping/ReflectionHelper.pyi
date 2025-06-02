from typing import List
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.data
import java.lang
import java.lang.reflect


class ReflectionHelper(object):




    def __init__(self): ...



    @staticmethod
    def assignField(field: java.lang.reflect.Field, obj: object, value: object) -> None:
        """
        Write a value to a field in a java class.
        @param field reflection {@link Field}
        @param obj java instance that contains the field
        @param value value to write
        @throws IOException if error accessing field or converting value
        """
        ...

    @staticmethod
    def callCtor(ctor: java.lang.reflect.Constructor, params: List[object]) -> object: ...

    @overload
    @staticmethod
    def callGetter(getterMethod: java.lang.reflect.Method, obj: object) -> object: ...

    @overload
    @staticmethod
    def callGetter(getterMethod: java.lang.reflect.Method, obj: object, expectedType: java.lang.Class) -> R: ...

    @staticmethod
    def callSetter(obj: object, setterMethod: java.lang.reflect.Method, value: object) -> None: ...

    @staticmethod
    def createInstance(__a0: java.lang.Class, __a1: object) -> object: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findGetter(structClass: java.lang.Class, getterName: unicode) -> java.lang.reflect.Method: ...

    @staticmethod
    def findSetter(fieldName: unicode, setterNameOverride: unicode, structClass: java.lang.Class, valueClass: java.lang.Class) -> java.lang.reflect.Method: ...

    @staticmethod
    def getAnnotations(targetClass: java.lang.Class, annotationClass: java.lang.Class, result: List[object]) -> List[object]: ...

    @staticmethod
    def getArrayOutputDataType(array_value: object, fieldType: java.lang.Class, length: int, signedness: ghidra.app.util.bin.format.golang.structmapping.Signedness, dataTypeMapper: ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper) -> ghidra.program.model.data.DataType:
        """
        Return Ghidra data type representing an array of primitive values.
        @param array_value java array object
        @param fieldType class representing the java array type
        @param length length of an element of the array, or -1
        @param signedness {@link Signedness} enum
        @param dataTypeMapper program level structure mapping context
        @return Ghdira {@link ArrayDataType} representing the specified java array type
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getCommentMethod(clazz: java.lang.Class, commentGetterName: unicode, defaultGetterName: unicode) -> java.lang.reflect.Method: ...

    @staticmethod
    def getCtor(__a0: java.lang.Class, __a1: List[java.lang.Class]) -> java.lang.reflect.Constructor: ...

    @staticmethod
    def getDataTypeSignedness(dt: ghidra.program.model.data.DataType) -> ghidra.app.util.bin.format.golang.structmapping.Signedness: ...

    @staticmethod
    def getFieldValue(obj: object, field: java.lang.reflect.Field, expectedType: java.lang.Class) -> R: ...

    @staticmethod
    def getMarkedMethods(__a0: java.lang.Class, __a1: java.lang.Class, __a2: List[object], __a3: bool, __a4: List[java.lang.Class]) -> List[object]: ...

    @staticmethod
    def getPrimitiveOutputDataType(fieldType: java.lang.Class, length: int, signedness: ghidra.app.util.bin.format.golang.structmapping.Signedness, dataTypeMapper: ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper) -> ghidra.program.model.data.DataType: ...

    @staticmethod
    def getPrimitiveSizeof(fieldType: java.lang.Class) -> int: ...

    @staticmethod
    def getPrimitiveWrapper(primitiveType: java.lang.Class) -> java.lang.Class: ...

    @staticmethod
    def hasStructureMapping(clazz: java.lang.Class) -> bool: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def invokeMethods(__a0: List[object], __a1: object, __a2: List[object]) -> None: ...

    @staticmethod
    def isPrimitiveType(clazz: java.lang.Class) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def requireGetter(clazz: java.lang.Class, getterName: unicode) -> java.lang.reflect.Method: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


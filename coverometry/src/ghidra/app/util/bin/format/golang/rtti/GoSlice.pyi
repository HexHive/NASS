from typing import List
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.format.golang.rtti
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.address
import ghidra.program.model.data
import java.lang


class GoSlice(object):




    @overload
    def __init__(self): ...

    @overload
    def __init__(self, array: long, len: long, cap: long): ...

    @overload
    def __init__(self, array: long, len: long, cap: long, programContext: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper): ...



    def equals(self, __a0: object) -> bool: ...

    def getArrayAddress(self) -> ghidra.program.model.address.Address: ...

    def getArrayEnd(self, elementClass: java.lang.Class) -> long: ...

    def getArrayOffset(self) -> long: ...

    def getCap(self) -> long: ...

    def getClass(self) -> java.lang.Class: ...

    def getLen(self) -> long: ...

    def getSubSlice(self, startElement: long, elementCount: long, elementSize: long) -> ghidra.app.util.bin.format.golang.rtti.GoSlice:
        """
        Return a artificial view of a portion of this slice's contents.
        @param startElement index of element that will be the new sub-slice's starting element
        @param elementCount number of elements to include in new sub-slice
        @param elementSize size of an individual element
        @return new {@link GoSlice} instance that is limited to a portion of this slice
        """
        ...

    def hashCode(self) -> int: ...

    def isFull(self) -> bool: ...

    def isOffsetWithinData(self, offset: long, sizeofElement: int) -> bool: ...

    @overload
    def isValid(self) -> bool: ...

    @overload
    def isValid(self, elementSize: int) -> bool: ...

    @overload
    def markupArray(self, sliceName: unicode, elementType: ghidra.program.model.data.DataType, ptr: bool, session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> None:
        """
        Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType.
        @param sliceName used to label the memory location
        @param elementType Ghidra datatype of the array elements, null ok if ptr == true
        @param ptr boolean flag, if true the element type is really a pointer to the supplied
         data type
        @param session state and methods to assist marking up the program
        @throws IOException if error
        """
        ...

    @overload
    def markupArray(self, sliceName: unicode, elementClazz: java.lang.Class, ptr: bool, session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> None:
        """
        Marks up the memory occupied by the array elements with a name and a Ghidra ArrayDataType,
         which has elements who's type is determined by the specified structure class.
        @param sliceName used to label the memory location
        @param elementClazz structure mapped class of the element of the array
        @param ptr boolean flag, if true the element type is really a pointer to the supplied
         data type
        @param session state and methods to assist marking up the program
        @throws IOException if error
        """
        ...

    def markupArrayElements(self, clazz: java.lang.Class, session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> List[object]:
        """
        Marks up each element of the array, useful when the elements are themselves structures.
        @param <T> element type
        @param clazz structure mapped class of element
        @param session state and methods to assist marking up the program
        @return list of element instances
        @throws IOException if error reading
        """
        ...

    def markupElementReferences(self, __a0: int, __a1: List[object], __a2: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def readList(self, readFunc: ghidra.app.util.bin.BinaryReader.ReaderFunction) -> List[object]:
        """
        Reads the contents of the slice, treating each element as an instance of an object that can
         be read using the supplied reading function.
        @param <T> struct mapped type of element
        @param readFunc function that will read an instance from a BinaryReader
        @return list of instances
        @throws IOException if error reading an element
        """
        ...

    @overload
    def readList(self, clazz: java.lang.Class) -> List[object]:
        """
        Reads the content of the slice, treating each element as an instance of the specified
         structure mapped class.
        @param <T> struct mapped type of element
        @param clazz element type
        @return list of instances
        @throws IOException if error reading an element
        """
        ...

    def readUIntList(self, intSize: int) -> List[long]:
        """
        Treats this slice as a array of unsigned integers, of the specified intSize.
         <p>
        @param intSize size of integer
        @return array of longs, containing the (possibly smaller) integers contained in the slice
        @throws IOException if error reading
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
    def arrayAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def arrayOffset(self) -> long: ...

    @property
    def cap(self) -> long: ...

    @property
    def full(self) -> bool: ...

    @property
    def len(self) -> long: ...

    @property
    def valid(self) -> bool: ...
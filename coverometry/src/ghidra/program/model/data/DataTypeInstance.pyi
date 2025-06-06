import ghidra.program.model.data
import ghidra.program.model.mem
import java.lang


class DataTypeInstance(object):
    """
    An instance of a DataType that is applicable for a given context.  Most
     dataTypes are not context sensitive and are suitable for use anywhere.
     Others like dynamic structures need to create an instance that wraps the
     data type.
 
     It helps for situations where a data type must have a length.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        @return the data type
        """
        ...

    @overload
    @staticmethod
    def getDataTypeInstance(dataType: ghidra.program.model.data.DataType, length: int, useAlignedLength: bool) -> ghidra.program.model.data.DataTypeInstance:
        """
        Attempt to create a fixed-length data-type instance.
         Factory and non-sizable Dynamic data-types are NOT handled.
         <br>
         This container does not dictate the placement of a fixed-length type within this
         container.  It is suggested that big-endian use should evaulate the datatype
         at the far end of the container.
        @param dataType data type
        @param length length for sizable Dynamic data-types, otherwise ignored
        @param useAlignedLength if true a fixed-length primitive data type will use its 
         {@link DataType#getAlignedLength() aligned-length}, otherwise it will use its
         {@link DataType#getLength() raw length}.  NOTE: This generally only relates to 
         float datatypes whose raw encoding length may be shorter than their aligned-length
         generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
         true for {@link DataTypeComponent} and false for simple {@link Data} instances.
        @return data-type instance or null if unable to create instance.
        """
        ...

    @overload
    @staticmethod
    def getDataTypeInstance(dataType: ghidra.program.model.data.DataType, buf: ghidra.program.model.mem.MemBuffer, useAlignedLength: bool) -> ghidra.program.model.data.DataTypeInstance:
        """
        Generate a data-type instance
         Factory and Dynamic data-types are NOT handled.
         <br>
         This container does not dictate the placement of a fixed-length type within this
         container.  It is suggested that big-endian use should evaulate the datatype
         at the far end of the container.
        @param dataType data type
        @param buf memory buffer
        @param useAlignedLength if true a fixed-length primitive data type will use its 
         {@link DataType#getAlignedLength() aligned-length}, otherwise it will use its
         {@link DataType#getLength() raw length}.  NOTE: This generally only relates to 
         float datatypes whose raw encoding length may be shorter than their aligned-length
         generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
         true for {@link DataTypeComponent} and false for simple {@link Data} instances.
        @return data-type instance or null if one could not be determined
        """
        ...

    @overload
    @staticmethod
    def getDataTypeInstance(dataType: ghidra.program.model.data.DataType, buf: ghidra.program.model.mem.MemBuffer, length: int, useAlignedLength: bool) -> ghidra.program.model.data.DataTypeInstance:
        """
        Attempt to create a data-type instance associated with a specific memory location.
         Factory and Dynamic data-types are handled.
         <br>
         This container does not dictate the placement of a fixed-length type within this
         container.  It is suggested that big-endian use should evaulate the datatype
         at the far end of the container.
        @param dataType the data type
        @param buf memory location
        @param length length for sizable Dynamic data-types, otherwise ignored
        @param useAlignedLength if true a fixed-length primitive data type will use its 
         {@link DataType#getAlignedLength() aligned-length}, otherwise it will use its
         {@link DataType#getLength() raw length}.  NOTE: This generally only relates to 
         float datatypes whose raw encoding length may be shorter than their aligned-length
         generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
         true for {@link DataTypeComponent} and false for simple {@link Data} instances.
        @return data-type instance or null if unable to create instance.
        """
        ...

    def getLength(self) -> int:
        """
        @return the fixed length of the data type
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setLength(self, length: int) -> None:
        """
        Set the length of this data type instance
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
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def length(self) -> int: ...

    @length.setter
    def length(self, value: int) -> None: ...
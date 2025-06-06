import ghidra.util
import ghidra.util.map
import java.io
import java.lang


class ObjectValueMap(ghidra.util.map.ValueMap):
    """
    Handles general storage and retrieval of object values indexed by long keys.
    """





    def __init__(self, name: unicode):
        """
        Constructor for ObjectPropertySet.
        @param name the name associated with this property set.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataSize(self) -> int:
        """
        @see ValueMap#getDataSize()
        """
        ...

    def getFirstPropertyIndex(self) -> long:
        """
        Get the first index where a property value exists.
        @throws NoSuchIndexException when there is no property value for any index.
        """
        ...

    def getLastPropertyIndex(self) -> long:
        """
        Get the last index where a property value exists.
        @exception NoSuchIndexException thrown if there is no address having the property value.
        """
        ...

    def getName(self) -> unicode:
        """
        Get the name for this property manager.
        """
        ...

    def getNextPropertyIndex(self, index: long) -> long:
        """
        Get the next index where the property value exists.
        @param index the address from which to begin the search (exclusive).
        @throws NoSuchIndexException thrown if there is no address with
           a property value after the given address.
        """
        ...

    def getObject(self, index: long) -> object:
        """
        Retrieves the object stored at the given index.
        @param index the index at which to retrieve the object.
        @return the object stored at the given index or null if no object is
         stored at the index.
        """
        ...

    def getObjectClass(self) -> java.lang.Class:
        """
        Returns property object class associated with this set.
        """
        ...

    def getPreviousPropertyIndex(self, index: long) -> long:
        """
        Get the previous index where a property value exists.
        @param index the long representation of an address from which
         		to begin the search (exclusive).
        @throws NoSuchIndexException when there is no index
         		with a property value before the given address.
        """
        ...

    @overload
    def getPropertyIterator(self) -> ghidra.util.LongIterator:
        """
        Returns an iterator over the indices having the given property
         value.
        """
        ...

    @overload
    def getPropertyIterator(self, start: long) -> ghidra.util.LongIterator:
        """
        Returns an iterator over the indices having the given property
         value.
        @param start the starting index for the iterator.
        """
        ...

    @overload
    def getPropertyIterator(self, start: long, end: long) -> ghidra.util.LongIterator:
        """
        Creates an iterator over all the indexes that have this property within
         the given range.
        @param start The start address to search
        @param end The end address to search
        @return LongIterator Iterator over indexes that have properties.
        """
        ...

    @overload
    def getPropertyIterator(self, start: long, before: bool) -> ghidra.util.LongIterator:
        """
        Returns an iterator over the indices having the given property
         value.
        @param start the starting index for the iterator.
        @param before if true the iterator will be positioned before the start value.
        """
        ...

    @overload
    def getPropertyIterator(self, start: long, end: long, atStart: bool) -> ghidra.util.LongIterator:
        """
        Creates an iterator over all the indexes that have this property within
         the given range.
        @param start The start address to search
        @param end The end address to search
        @param atStart indicates if the iterator should begin at the start
         address, otherwise it will start at the last address.  Set this flag to
         false if you want to iterate backwards through the properties.
        @return LongIterator Iterator over indexes that have properties.
        """
        ...

    def getSize(self) -> int:
        """
        Get the number of properties in the set.
        @return the number of properties
        """
        ...

    def hasProperty(self, index: long) -> bool:
        """
        returns whether there is a property value at index.
        @param index the long representation of an address.
        """
        ...

    def hashCode(self) -> int: ...

    def intersects(self, start: long, end: long) -> bool:
        """
        Given two indices it indicates whether there is an index in
         that range (inclusive) having the property.<p>
        @param start the start of the index range.
        @param end the end of the index range.
        @return boolean true if at least one index in the range
         has the property, false otherwise.
        """
        ...

    def moveRange(self, start: long, end: long, newStart: long) -> None:
        """
        Move the range of properties to the newStart index.
        @param start the beginning of the property range to move
        @param end the end of the property range to move
        @param newStart the new beginning of the property range after the move
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def putObject(self, index: long, value: object) -> None:
        """
        Stores an object at the given index.  Any object currently at that index
         will be replaced by the new object.
        @param index the index at which to store the object.
        @param value the object to store.
        """
        ...

    def remove(self, index: long) -> bool:
        """
        Remove the property value at the given index.
        @return true if the property value was removed, false
           otherwise.
        @param index the long representation of an address.
        """
        ...

    def removeRange(self, start: long, end: long) -> bool:
        """
        Removes all property values within a given range.
        @param start begin range
        @param end end range, inclusive
        @return true if any property value was removed; return
         		false otherwise.
        """
        ...

    def restoreProperties(self, ois: java.io.ObjectInputStream) -> None:
        """
        Restores all the properties from the input stream.  Any existing
         properties will first be removed.
        @param ois the input stream.
        @throws IOException if I/O error occurs.
        @throws ClassNotFoundException if the a class cannot be determined for
         the property value.
        """
        ...

    def saveProperties(self, oos: java.io.ObjectOutputStream, start: long, end: long) -> None:
        """
        Saves all property values between start and end to the output stream
        @param oos the output stream
        @param start the first index in the range to save.
        @param end the last index in the range to save.
        @throws IOException if an I/O error occurs on the write.
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
    def dataSize(self) -> int: ...
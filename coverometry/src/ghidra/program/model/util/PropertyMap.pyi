import ghidra.program.model.address
import java.lang


class PropertyMap(object):
    """
    Interface to define a map containing properties over a set of addresses.
    """









    def add(self, addr: ghidra.program.model.address.Address, value: object) -> None:
        """
        Add a map-specific value type to the specified address
        @param addr property address
        @param value property value or null (null remove value at address)
        @throws IllegalArgumentException if property value type is inappropriate for this map
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, addr: ghidra.program.model.address.Address) -> object:
        """
        Returns the property value stored at the specified 
         address or null if no property found.
        @param addr property address
        @return property value
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFirstPropertyAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the first Address where a property value exists.
        @return first property value location or null if none found
        """
        ...

    def getLastPropertyAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the last Address where a property value exists.
        @return last property value location or null if none found
        """
        ...

    def getName(self) -> unicode:
        """
        Get the name for this property map.
        @return map name
        """
        ...

    def getNextPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Get the next address where the property value exists.
        @param addr the address from which to begin the search (exclusive).
        @return property value location after specified {@code addr} or null if none found
        """
        ...

    def getPreviousPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Get the previous Address where a property value exists.
        @param addr the address from which to begin the search (exclusive).
        @return property value location after specified {@code addr} or null if none found
        """
        ...

    @overload
    def getPropertyIterator(self) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the addresses that a property value.
        @return forward property address iterator
        """
        ...

    @overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the addresses that have a property value and
         are in the given address set.
        @param asv the set of addresses to iterate over.
        @return forward property address iterator
        """
        ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the address having a property value.
        @param start the starting address
        @param forward if true will iterate in increasing address order, otherwise it will start at
         the end and iterate in decreasing address order
        @return property address iterator
        """
        ...

    @overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the addresses that have a property value and
         are in the given address set.
        @param asv the set of addresses to iterate over.
        @param forward if true will iterate in increasing address order, otherwise it will start at
         the end and iterate in decreasing address order
        @return property address iterator
        """
        ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over the indices having a property value.
        @param start minimum address
        @param end maximum address
        @return forward property address iterator
        """
        ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over addresses that have a property value.
        @param start minimum address
        @param end maximum address
        @param forward if true will iterate in increasing address order, otherwise it will start at
         the end and iterate in decreasing address order
        @return property address iterator
        """
        ...

    def getSize(self) -> int:
        """
        Get the number of properties in the map.
        @return number of stored property values
        """
        ...

    def getValueClass(self) -> java.lang.Class:
        """
        Returns property value class.
        @return property value class or null for an unsupported map type
        """
        ...

    def hasProperty(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        returns whether there is a property value at addr.
        @param addr the address in question
        @return true if map has value at specified address
        """
        ...

    def hashCode(self) -> int: ...

    @overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Indicate whether there is an address within
         the set which exists within this map.<p>
        @param set set of addresses
        @return boolean true if at least one address in the set
         has the property, false otherwise.
        """
        ...

    @overload
    def intersects(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Given two addresses, indicate whether there is an address in
         that range (inclusive) having the property.<p>
        @param start the start of the range.
        @param end the end of the range.
        @return boolean true if at least one address in the range
         has the property, false otherwise.
        """
        ...

    def moveRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, newStart: ghidra.program.model.address.Address) -> None:
        """
        Moves the properties defined in the range from the start address thru the 
         end address to now be located beginning at the newStart address. 
         The moved properties will be located at the same relative location to 
         the newStart address as they were previously to the start address.
        @param start the start of the range to move.
        @param end the end of the range to move.
        @param newStart the new start location of the range of properties 
         after the move.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Remove the property value at the given address.
        @return true if the property value was removed, false
           otherwise.
        @param addr the address where the property should be removed
        """
        ...

    def removeRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Removes all property values within a given range.
        @param start begin range
        @param end end range, inclusive
        @return true if any property value was removed; return
         		false otherwise.
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
    def firstPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def lastPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def name(self) -> unicode: ...

    @property
    def propertyIterator(self) -> ghidra.program.model.address.AddressIterator: ...

    @property
    def size(self) -> int: ...

    @property
    def valueClass(self) -> java.lang.Class: ...
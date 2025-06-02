import ghidra.program.model.address
import ghidra.program.model.util
import java.lang


class VoidPropertyMap(ghidra.program.model.util.PropertyMap, object):
    """
    Property manager that deals with properties that are of
     "void" type, which is a marker for whether a property exists.
     Object values returned are either Boolean#TRUE or null.
    """









    @overload
    def add(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Mark the specified address as having a property
        @param addr address for the property
        """
        ...

    @overload
    def add(self, addr: ghidra.program.model.address.Address, value: object) -> None:
        """
        Apply property value to specified address.
        @param addr property address
        @param value boolean value (null or false will remove property value)
        @throws IllegalArgumentException if value specified is not a Boolean or null
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, __a0: ghidra.program.model.address.Address) -> object: ...

    def getClass(self) -> java.lang.Class: ...

    def getFirstPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    def getLastPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    def getName(self) -> unicode: ...

    def getNextPropertyAddress(self, __a0: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    def getPreviousPropertyAddress(self, __a0: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    @overload
    def getPropertyIterator(self) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, __a0: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, __a0: ghidra.program.model.address.Address, __a1: bool) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, __a0: ghidra.program.model.address.AddressSetView, __a1: bool) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address, __a2: bool) -> ghidra.program.model.address.AddressIterator: ...

    def getSize(self) -> int: ...

    def getValueClass(self) -> java.lang.Class: ...

    def hasProperty(self, __a0: ghidra.program.model.address.Address) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def intersects(self, __a0: ghidra.program.model.address.AddressSetView) -> bool: ...

    @overload
    def intersects(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address) -> bool: ...

    def moveRange(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self, __a0: ghidra.program.model.address.Address) -> bool: ...

    def removeRange(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address) -> bool: ...

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
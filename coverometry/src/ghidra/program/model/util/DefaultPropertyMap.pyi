import ghidra.program.model.address
import ghidra.program.model.util
import java.io
import java.lang


class DefaultPropertyMap(object, ghidra.program.model.util.PropertyMap):
    """
    PropertyMap is used to store values for a fixed property at
       address locations given as longs. The values for the property
       must be homogeneous, i.e. all have the same type, and are
       determined by which subclass of PropertyMap is instantiated.
       For any long the property
       manager can be used to tell if the property exists there and
       what its value is. It also maintains information that allows it
       to efficiently search for the next and previous occurrence of the
       property relative to a given address.
       The subclass provides the createPage() method that dictates
      the type of PropertyPage that will be managed.
    """





    def __init__(self, propertyMgr: ghidra.util.map.ValueMap):
        """
        Construct a PropertyMap
        @param propertyMgr property manager that manages storage of
         properties
        """
        ...



    def add(self, __a0: ghidra.program.model.address.Address, __a1: object) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, __a0: ghidra.program.model.address.Address) -> object: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        Return the property description.
        @return the property description
        """
        ...

    def getFirstPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    def getLastPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    def getName(self) -> unicode: ...

    def getNextPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    def getPreviousPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    @overload
    def getPropertyIterator(self) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    def getSize(self) -> int: ...

    def getValueClass(self) -> java.lang.Class: ...

    def hasProperty(self, addr: ghidra.program.model.address.Address) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool: ...

    @overload
    def intersects(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool: ...

    def moveRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, newStart: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self, addr: ghidra.program.model.address.Address) -> bool: ...

    def removeRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool: ...

    def restoreProperties(self, ois: java.io.ObjectInputStream) -> None:
        """
        Restore properties from the given input stream.
        @param ois input stream
        @throws IOException if there is a problem reading from the stream
        @throws ClassNotFoundException if the class for the object being
         read is not in the class path
        """
        ...

    def saveProperties(self, oos: java.io.ObjectOutputStream, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Save the properties in the given range to output stream.
        @param oos output stream to write to
        @param start start address in the range
        @param end end address in the range
        @throws IOException if there a problem doing the write
        """
        ...

    def setDescription(self, description: unicode) -> None:
        """
        Set the description for this property.
        @param description property description
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
    def description(self) -> unicode: ...

    @description.setter
    def description(self, value: unicode) -> None: ...

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
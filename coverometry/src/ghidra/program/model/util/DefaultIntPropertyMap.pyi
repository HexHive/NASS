import ghidra.program.model.address
import ghidra.program.model.util
import java.io
import java.lang


class DefaultIntPropertyMap(ghidra.program.model.util.DefaultPropertyMap, ghidra.program.model.util.IntPropertyMap):
    """
    Property manager that deals with properties that are of
     int type.
    """





    def __init__(self, name: unicode):
        """
        Construct a new IntPropertyMap
        @param name name of property
        """
        ...



    @overload
    def add(self, addr: ghidra.program.model.address.Address, value: int) -> None: ...

    @overload
    def add(self, __a0: ghidra.program.model.address.Address, __a1: object) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, addr: ghidra.program.model.address.Address) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        Return the property description.
        @return the property description
        """
        ...

    def getFirstPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    def getInt(self, addr: ghidra.program.model.address.Address) -> int: ...

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


from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang
import java.util


class PcodeFactory(object):
    """
    Interface for classes that build PcodeOps and Varnodes
    """









    def buildStorage(self, vn: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.listing.VariableStorage:
        """
        Build a storage object for a particular Varnode
        @param vn is the Varnode
        @return the storage object
        @throws InvalidInputException if valid storage cannot be created
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        @return Address factory
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDataTypeManager(self) -> ghidra.program.model.pcode.PcodeDataTypeManager:
        """
        @return pcode data type manager used to convert strings to Ghidra data types
        """
        ...

    def getJoinAddress(self, storage: ghidra.program.model.listing.VariableStorage) -> ghidra.program.model.address.Address:
        """
        Get the address (in the "join" space) corresponding to the given multi-piece storage.
         The storage must have been previously registered by a previous call to getJoinStorage().
         If the storage is not multi-piece or was not registered, null is returned.
        @param storage is the multi-piece storage
        @return the corresponding "join" address
        """
        ...

    def getJoinStorage(self, pieces: List[ghidra.program.model.pcode.Varnode]) -> ghidra.program.model.listing.VariableStorage:
        """
        Create a storage object representing a value split across multiple physical locations.
         The sequence of physical locations are passed in as an array of Varnodes and the storage
         object is returned.  The storage is also assigned an Address in the join address space,
         which can be retrieved by calling the getJoinAddress() method.  The join Address can
         be used to create a Varnode that represents the logical whole created by concatenating
         the Varnode pieces.
        @param pieces is the array of Varnode pieces to join
        @return the VariableStorage representing the whole
        @throws InvalidInputException if a valid storage object cannot be created
        """
        ...

    def getOpRef(self, refid: int) -> ghidra.program.model.pcode.PcodeOp:
        """
        Get a PcodeOp given a reference id.  The reference id corresponds to the op's
         SequenceNumber.getTime() field.  Return null if no op matching the id has been registered
         via newOp().
        @param refid is the reference id
        @return the matching PcodeOp or null
        """
        ...

    def getRef(self, refid: int) -> ghidra.program.model.pcode.Varnode:
        """
        Return a Varnode given its reference id, or null if the id is not registered.
         The id must have previously been registered via newVarnode().
        @param refid is the reference id
        @return the matching Varnode or null
        """
        ...

    def getSymbol(self, symbolId: long) -> ghidra.program.model.pcode.HighSymbol:
        """
        Get the high symbol matching the given id that has been registered with this object
        @param symbolId is the given id
        @return the matching HighSymbol or null
        """
        ...

    def hashCode(self) -> int: ...

    def newOp(self, __a0: ghidra.program.model.pcode.SequenceNumber, __a1: int, __a2: java.util.ArrayList, __a3: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.pcode.PcodeOp: ...

    @overload
    def newVarnode(self, sz: int, addr: ghidra.program.model.address.Address) -> ghidra.program.model.pcode.Varnode:
        """
        Create a new Varnode with the given size and location
        @param sz size of the Varnode
        @param addr location of the Varnode
        @return a new varnode
        """
        ...

    @overload
    def newVarnode(self, sz: int, addr: ghidra.program.model.address.Address, refId: int) -> ghidra.program.model.pcode.Varnode:
        """
        Create a new Varnode with the given size and location.
         Associate the Varnode with a specific reference id so that it can be retrieved,
         using just the id, via getRef();
        @param sz size of the Varnode
        @param addr location of the Varnode
        @param refId is the specific reference id
        @return the new Varnode
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setAddrTied(self, vn: ghidra.program.model.pcode.Varnode, val: bool) -> None:
        """
        Mark (or unmark) the given Varnode with the "address tied" property
        @param vn is the given Varnode
        @param val is true if the Varnode should be marked
        """
        ...

    def setDataType(self, vn: ghidra.program.model.pcode.Varnode, type: ghidra.program.model.data.DataType) -> None:
        """
        Attach a data-type to the given Varnode
        @param vn is the given Varnode
        @param type is the data-type
        """
        ...

    def setInput(self, vn: ghidra.program.model.pcode.Varnode, val: bool) -> ghidra.program.model.pcode.Varnode:
        """
        Mark (or unmark) the given Varnode as an input (to its function)
        @param vn is the given Varnode
        @param val is true if the Varnode should be marked
        @return the altered Varnode, which may not be the same object passed in
        """
        ...

    def setMergeGroup(self, vn: ghidra.program.model.pcode.Varnode, val: int) -> None:
        """
        Associate a specific merge group with the given Varnode
        @param vn is the given Varnode
        @param val is the merge group
        """
        ...

    def setPersistent(self, vn: ghidra.program.model.pcode.Varnode, val: bool) -> None:
        """
        Mark (or unmark) the given Varnode with the "persistent" property
        @param vn is the given Varnode
        @param val is true if the Varnode should be marked
        """
        ...

    def setUnaffected(self, vn: ghidra.program.model.pcode.Varnode, val: bool) -> None:
        """
        Mark (or unmark) the given Varnode with the "unaffected" property
        @param vn is the given Varnode
        @param val is true if the Varnode should be marked
        """
        ...

    def setVolatile(self, vn: ghidra.program.model.pcode.Varnode, val: bool) -> None:
        """
        Mark (or unmark) the given Varnode with the "volatile" property
        @param vn is the given Varnode
        @param val is true if the Varnode should be marked volatile
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
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.pcode.PcodeDataTypeManager: ...
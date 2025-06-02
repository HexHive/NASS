from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang


class ReferenceManager(object):
    """
    Interface for managing references.
    """

    MNEMONIC: int = -1







    @overload
    def addExternalReference(self, fromAddr: ghidra.program.model.address.Address, opIndex: int, location: ghidra.program.model.symbol.ExternalLocation, source: ghidra.program.model.symbol.SourceType, type: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
        """
        Adds an external reference.  If a reference already
         exists for the fromAddr and opIndex, the existing reference is replaced
         with the new reference.
        @param fromAddr from memory address (source of the reference)
        @param opIndex operand index
        @param location external location
        @param source the source of this reference
        @param type reference type - how the location is being referenced
        @return external reference
        @throws InvalidInputException
        """
        ...

    @overload
    def addExternalReference(self, fromAddr: ghidra.program.model.address.Address, libraryName: unicode, extLabel: unicode, extAddr: ghidra.program.model.address.Address, source: ghidra.program.model.symbol.SourceType, opIndex: int, type: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
        """
        Adds an external reference to an external symbol.  If a reference already
         exists at {@code fromAddr} and {@code opIndex} the existing reference is replaced
         with a new reference.  If the external symbol cannot be found, a new {@link Library} 
         and/or {@link ExternalLocation} symbol will be created which corresponds to the specified
         library/file named {@code libraryName}
         and the location within that file identified by {@code extLabel} and/or its memory address
         {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
        @param fromAddr from memory address (source of the reference)
        @param libraryName name of external program
        @param extLabel label within the external program, may be null if extAddr is not null
        @param extAddr memory address within the external program, may be null
        @param source the source of this reference
        @param opIndex operand index
        @param type reference type - how the location is being referenced
        @return new external space reference
        @throws InvalidInputException if {@code libraryName} is invalid or null, or an invalid 
         {@code extlabel} is specified.  Names with spaces or the empty string are not permitted.
         Neither {@code extLabel} nor {@code extAddr} was specified properly.
        @throws DuplicateNameException if another non-Library namespace has the same name
        @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
        """
        ...

    @overload
    def addExternalReference(self, fromAddr: ghidra.program.model.address.Address, extNamespace: ghidra.program.model.symbol.Namespace, extLabel: unicode, extAddr: ghidra.program.model.address.Address, source: ghidra.program.model.symbol.SourceType, opIndex: int, type: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
        """
        Adds an external reference.  If a reference already
         exists for the fromAddr and opIndex, the existing reference is replaced
         with the new reference.
        @param fromAddr from memory address (source of the reference)
        @param extNamespace external namespace containing the named external label.
        @param extLabel label within the external program, may be null if extAddr is not null
        @param extAddr address within the external program, may be null
        @param source the source of this reference
        @param opIndex operand index
        @param type reference type - how the location is being referenced
        @return new external space reference
        @throws InvalidInputException if an invalid {@code extlabel} is specified.  
         Names with spaces or the empty string are not permitted.
         Neither {@code extLabel} nor {@code extAddr} was specified properly.
        @throws DuplicateNameException if another non-Library namespace has the same name
        @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
        """
        ...

    def addMemoryReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, type: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: int) -> ghidra.program.model.symbol.Reference:
        """
        Adds a memory reference.  The first memory reference placed on
         an operand will be made primary by default.  All non-memory references 
         will be removed from the specified operand.  Certain reference {@link RefType types}
         may not be specified (e.g., {@link RefType#FALL_THROUGH}).
        @param fromAddr address of the codeunit where the reference occurs
        @param toAddr address of the location being referenced.  
         Memory, stack, and register addresses are all permitted.
        @param type reference type - how the location is being referenced.
        @param source the source of this reference
        @param opIndex the operand index 
         display of the operand making this reference
        @return new memory reference
        @throws IllegalArgumentException if unsupported {@link RefType type} is specified
        """
        ...

    def addOffsetMemReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, toAddrIsBase: bool, offset: long, type: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: int) -> ghidra.program.model.symbol.Reference:
        """
        Add an offset memory reference.  The first memory reference placed on
         an operand will be made primary by default.  All non-memory references 
         will be removed from the specified operand.  If toAddr corresponds to
         the EXTERNAL memory block (see {@link MemoryBlock#EXTERNAL_BLOCK_NAME}) the
         resulting offset reference will report to/base address as the same
         regardless of specified offset.
        @param fromAddr address for the "from"
        @param toAddr address of the location being referenced.
        @param toAddrIsBase if true toAddr is treated as base address, else treated as (base+offet).
         It is generally preferred to specify as a base address to ensure proper handling of
         EXTERNAL block case.
        @param offset value added to a base address to get the toAddr
        @param type reference type - how the location is being referenced
        @param source the source of this reference
        @param opIndex the operand index
        @return new offset reference
        """
        ...

    def addReference(self, reference: ghidra.program.model.symbol.Reference) -> ghidra.program.model.symbol.Reference:
        """
        Add a memory, stack, register or external reference
        @param reference reference to be added
        @return new reference
        """
        ...

    def addRegisterReference(self, fromAddr: ghidra.program.model.address.Address, opIndex: int, register: ghidra.program.model.lang.Register, type: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Reference:
        """
        Add a reference to a register. If a reference already
         exists for the fromAddr and opIndex, the existing reference is replaced
         with the new reference.
        @param fromAddr "from" address
        @param opIndex operand index
        @param register register to add the reference to
        @param type reference type - how the location is being referenced.
        @param source the source of this reference
        @return new register reference
        """
        ...

    def addShiftedMemReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, shiftValue: int, type: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType, opIndex: int) -> ghidra.program.model.symbol.Reference:
        """
        Add a shifted memory reference; the "to" address is computed as the value
         at the operand at opIndex shifted by some number of bits, specified in the 
         shiftValue parameter.  The first memory reference placed on
         an operand will be made primary by default.  All non-memory references 
         will be removed from the specified operand.
        @param fromAddr source/from memory address
        @param toAddr destination/to memory address computed as some 
         {@link ShiftedReference#getValue() base offset value} shifted left
         by the number of bits specified by shiftValue.  The least-significant bits of toAddr
         offset should be 0's based upon the specified shiftValue since this value is shifted
         right to calculate the base offset value.
        @param shiftValue number of bits to shift
        @param type reference type - how the location is being referenced
        @param source the source of this reference
        @param opIndex the operand index
        @return new shifted reference
        """
        ...

    def addStackReference(self, fromAddr: ghidra.program.model.address.Address, opIndex: int, stackOffset: int, type: ghidra.program.model.symbol.RefType, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Reference:
        """
        Add a reference to a stack location. If a reference already
         exists for the fromAddr and opIndex, the existing reference is replaced
         with the new reference.
        @param fromAddr "from" address within a function
        @param opIndex operand index
        @param stackOffset stack offset of the reference
        @param type reference type - how the location is being referenced.
        @param source the source of this reference
        @return new stack reference
        """
        ...

    def delete(self, ref: ghidra.program.model.symbol.Reference) -> None:
        """
        Deletes the given reference object
        @param ref the reference to be deleted.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getExternalReferences(self) -> ghidra.program.model.symbol.ReferenceIterator:
        """
        Returns an iterator over all external space references
        @return reference iterator over all external space references
        """
        ...

    def getFlowReferencesFrom(self, addr: ghidra.program.model.address.Address) -> List[ghidra.program.model.symbol.Reference]:
        """
        Get all flow references from the given address.
        @param addr the address of the codeunit to get all flows from.
        @return get all flow references from the given address.
        """
        ...

    def getPrimaryReferenceFrom(self, addr: ghidra.program.model.address.Address, opIndex: int) -> ghidra.program.model.symbol.Reference:
        """
        Get the primary reference from the given address.
        @param addr from address
        @param opIndex operand index
        @return the primary reference from the specified address
         and opindex if it exists, else null
        """
        ...

    def getReference(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, opIndex: int) -> ghidra.program.model.symbol.Reference:
        """
        Get the reference that has the given from and to address, and
         operand index.
        @param fromAddr the address of the codeunit making the reference.
        @param toAddr the address being referred to.
        @param opIndex the operand index.
        @return reference which satisfies the specified criteria or null
        """
        ...

    def getReferenceCountFrom(self, fromAddr: ghidra.program.model.address.Address) -> int:
        """
        Returns the number of references from the specified <code>fromAddr</code>.
        @param fromAddr the address of the codeunit making the reference.
        @return the number of references from the specified <code>fromAddr</code>.
        """
        ...

    def getReferenceCountTo(self, toAddr: ghidra.program.model.address.Address) -> int:
        """
        Returns the number of references to the specified <code>toAddr</code>.
        @param toAddr the address being referenced
        @return the number of references to the specified <code>toAddr</code>.
        """
        ...

    def getReferenceDestinationCount(self) -> int:
        """
        Return the number of references for "to" addresses.
        """
        ...

    @overload
    def getReferenceDestinationIterator(self, startAddr: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over all addresses that are the "To" address in a
         reference.
        @param startAddr start of iterator
        @param forward true means to iterate in the forward direction
         address iterator where references to exist
        @return address iterator where references to exist
        """
        ...

    @overload
    def getReferenceDestinationIterator(self, addrSet: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over all addresses that are the "To" address in a
         memory reference, restricted by the given address set.
        @param addrSet the set of address to restrict the iterator or null for all addresses.
        @param forward true means to iterate in the forward direction
        @return address iterator where references to exist constrained by addrSet
        """
        ...

    def getReferenceIterator(self, startAddr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.ReferenceIterator:
        """
        Get an iterator over references starting with the specified 
         fromAddr.  A forward iterator is returned with references sorted on
         the from address.
        @param startAddr the first from address to consider.
        @return a forward memory reference iterator.
        """
        ...

    def getReferenceLevel(self, toAddr: ghidra.program.model.address.Address) -> int:
        """
        Returns the reference level for the references to the given address
        @param toAddr the address at which to find the highest reference level
        @return reference level for specified to address.
        """
        ...

    def getReferenceSourceCount(self) -> int:
        """
        Return the number of references for "from" addresses.
        """
        ...

    @overload
    def getReferenceSourceIterator(self, startAddr: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over addresses that are the "From" address in a
         reference
        @param startAddr address to position iterator.
        @param forward true means to iterate in the forward direction
        @return address iterator where references from exist
        """
        ...

    @overload
    def getReferenceSourceIterator(self, addrSet: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Returns an iterator over all addresses that are the "From" address in a
         reference, restricted by the given address set.
        @param addrSet the set of address to restrict the iterator or null for all addresses.
        @param forward true means to iterate in the forward direction
         address iterator where references from exist
        @return address iterator where references from exist constrained by addrSet
        """
        ...

    def getReferencedVariable(self, reference: ghidra.program.model.symbol.Reference) -> ghidra.program.model.listing.Variable:
        """
        Returns the referenced function variable.
        @param reference variable reference
        @return function variable or null if variable not found
        """
        ...

    @overload
    def getReferencesFrom(self, addr: ghidra.program.model.address.Address) -> List[ghidra.program.model.symbol.Reference]:
        """
        Get all references "from" the specified addr.
        @param addr address of code-unit making the references.
        @return array of all references "from" the specified addr.
        """
        ...

    @overload
    def getReferencesFrom(self, fromAddr: ghidra.program.model.address.Address, opIndex: int) -> List[ghidra.program.model.symbol.Reference]:
        """
        Returns all references "from" the given fromAddr and operand (specified by opIndex).
        @param fromAddr the from which to get references
        @param opIndex the operand from which to get references
        @return all references "from" the given fromAddr and operand.
        """
        ...

    @overload
    def getReferencesTo(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.ReferenceIterator:
        """
        Get an iterator over all references that have the given address as
         their "To" address.
        @param addr the address that all references in the iterator refer to.
        @return reference iterator over all references to the specified address.
        """
        ...

    @overload
    def getReferencesTo(self, var: ghidra.program.model.listing.Variable) -> List[ghidra.program.model.symbol.Reference]:
        """
        Returns all references to the given variable.  Only data references to storage 
         are considered.
        @param var variable to retrieve references to
        @return array of variable references, or zero length array if no
         references exist
        """
        ...

    def hasFlowReferencesFrom(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Return whether the given address has flow references from it.
        @param addr the address to test for flow references.
        @return true if the given address has flow references from it, else false
        """
        ...

    @overload
    def hasReferencesFrom(self, fromAddr: ghidra.program.model.address.Address) -> bool:
        """
        Returns true if there are any memory references at the given
         address.
        @param fromAddr the address of the codeunit being tested
        @return true if one or more reference from the specified address
         are defined, else false
        """
        ...

    @overload
    def hasReferencesFrom(self, fromAddr: ghidra.program.model.address.Address, opIndex: int) -> bool:
        """
        Returns true if there are any memory references at the given
         address/opIndex.  Keep in mind this is a rather inefficient 
         method as it must examine all references from the specified 
         fromAddr.
        @param fromAddr the address of the codeunit being tested
        @param opIndex the index of the operand being tested.
        @return true if one or more reference from the specified address
         and opindex are defined, else false
        """
        ...

    def hasReferencesTo(self, toAddr: ghidra.program.model.address.Address) -> bool:
        """
        Return true if a memory reference exists with the given "to" address.
        @param toAddr address being referred to.
        @return true if specified toAddr has one or more references to it, else false.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def removeAllReferencesFrom(self, fromAddr: ghidra.program.model.address.Address) -> None:
        """
        Remove all stack, external, and memory references for the given
         from address.
        @param fromAddr the address of the codeunit from which to remove all references.
        """
        ...

    @overload
    def removeAllReferencesFrom(self, beginAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> None:
        """
        Removes all references where "From address" is in the given range.
        @param beginAddr the first address in the range.
        @param endAddr the last address in the range.
        """
        ...

    def removeAllReferencesTo(self, toAddr: ghidra.program.model.address.Address) -> None:
        """
        Remove all stack, external, and memory references for the given
         to address.
        @param toAddr the address for which all references to should be removed.
        """
        ...

    def removeAssociation(self, ref: ghidra.program.model.symbol.Reference) -> None:
        """
        Removes any symbol associations with the given reference.
        @param ref the reference for which any symbol association is to be removed.
        @throws IllegalArgumentException if the given references does not exist.
        """
        ...

    def setAssociation(self, s: ghidra.program.model.symbol.Symbol, ref: ghidra.program.model.symbol.Reference) -> None:
        """
        Associates the given reference with the given symbol.
         Applies to memory references only where a specified label symbol must have 
         an address which matches the reference to-address.  Stack and register 
         reference associations to variable symbols are always inferred.
        @param s the symbol to associate with the given reference.
        @param ref the reference to associate with the given symbol
        @throws IllegalArgumentException If the given reference does not already
         exist or its "To" address
         is not the same as the symbol's address.
        """
        ...

    def setPrimary(self, ref: ghidra.program.model.symbol.Reference, isPrimary: bool) -> None:
        """
        Set the given reference's primary attribute
        @param ref the reference to make primary.
        @param isPrimary true to make the reference primary, false to make it non-primary
        """
        ...

    def toString(self) -> unicode: ...

    def updateRefType(self, ref: ghidra.program.model.symbol.Reference, refType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
        """
        Uodate the reference type on a memory reference.
        @param ref reference to be updated
        @param refType new reference type
        @return updated reference
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def externalReferences(self) -> ghidra.program.model.symbol.ReferenceIterator: ...

    @property
    def referenceDestinationCount(self) -> int: ...

    @property
    def referenceSourceCount(self) -> int: ...
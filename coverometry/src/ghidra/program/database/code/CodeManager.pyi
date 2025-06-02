from typing import Iterator
from typing import List
import db.util
import ghidra.program.database
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.model.util
import ghidra.util.task
import java.io
import java.lang


class CodeManager(object, db.util.ErrorHandler, ghidra.program.database.ManagerDB):
    """
    Class to manage database tables for data and instructions.
    """





    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: int, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new CodeManager for a program.
        @param handle handle to database
        @param addrMap addressMap to convert between addresses and long values.
        @param openMode either READ_ONLY, UPDATE, or UPGRADE
        @param lock the program synchronization lock
        @param monitor the task monitor use while upgrading.
        @throws VersionException if the database is incompatible with the current schema
        @throws IOException if a database io error occurs
        @throws CancelledException if the user cancels the upgrade operation
        """
        ...



    def activateContextLocking(self) -> None: ...

    def addInstructions(self, instructionSet: ghidra.program.model.lang.InstructionSet, overwrite: bool) -> ghidra.program.model.address.AddressSetView:
        """
        Creates a complete set of instructions.  A preliminary pass will be made checking for code 
         unit conflicts which will be marked within the instructionSet causing dependent blocks to 
         get pruned.
        @param instructionSet the set of instructions to be added. All code unit conflicts will be
         marked within the instructionSet and associated blocks.
        @param overwrite if true, overwrites existing code units.
        @return the set of addresses over which instructions were actually added to the program. 
         This may differ from the InstructionSet address set if conflict errors occurred. Such 
         conflict errors will be recorded within the InstructionSet and its InstructionBlocks.
        """
        ...

    def checkContextWrite(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Check if any instruction intersects the specified address range
        @param start start of range
        @param end end of range
        @throws ContextChangeException if there is a context register change conflict
        """
        ...

    def clearAll(self, clearContext: bool, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Clear all code units in the program.
        @param clearContext true to clear the context
        @param monitor the task monitor
        """
        ...

    def clearCodeUnits(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, clearContext: bool, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Remove code units, symbols, equates, and references to code units in the given range 
         (inclusive).  Comments and comment history will be retained.
        @param start the start address of the range to clear
        @param end the end address of the range to clear
        @param clearContext if true all context-register values will be cleared over range
        @param monitor the task monitor
        @throws CancelledException if cancelled
        """
        ...

    def clearComments(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Clears all comments in the given range (inclusive).
        @param start the start address of the range to clear
        @param end the end address of the range to clear
        """
        ...

    def clearData(self, dataTypeIDs: List[long], monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Removes any data objects that have dataTypes matching the given dataType ids.
        @param dataTypeIDs the list of ids of dataTypes that have been deleted.
        @param monitor the task monitor.
        @throws CancelledException if cancelled
        """
        ...

    def clearProperties(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Clears the properties in the given range (inclusive).
        @param start the start address of the range to clear
        @param end the end address of the range to clear
        @param monitor the task monitor
        @throws CancelledException if cancelled
        """
        ...

    @overload
    def createCodeUnit(self, addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, length: int) -> ghidra.program.model.listing.Data:
        """
        Creates a data at the specified address.
        @param addr Starting address of code unit
        @param dataType data prototype for the code unit
        @param length the data length
        @return the data
        @exception CodeUnitInsertionException if the code unit overlaps with an existing code unit
        """
        ...

    @overload
    def createCodeUnit(self, address: ghidra.program.model.address.Address, prototype: ghidra.program.model.lang.InstructionPrototype, memBuf: ghidra.program.model.mem.MemBuffer, context: ghidra.program.model.lang.ProcessorContextView, length: int) -> ghidra.program.model.listing.Instruction:
        """
        Creates an instruction at the specified address.
        @param address start address of instruction
        @param prototype instruction definition object
        @param memBuf the MemBuffer to use to get the bytes from memory
        @param context object that has the state of all the registers.
        @param length instruction byte-length (must be in the range 0..prototype.getLength()).
         If smaller than the prototype length it must have a value no greater than 7, otherwise
         an error will be thrown.  A value of 0 or greater-than-or-equal the prototype length
         will be ignored and not impose and override length.  The length value must be a multiple 
         of the {@link Language#getInstructionAlignment() instruction alignment} .
        @return the newly created instruction.
        @throws CodeUnitInsertionException thrown if the new Instruction would overlap and 
         existing {@link CodeUnit} or the specified {@code length} is unsupported.
        @throws IllegalArgumentException if a negative {@code length} is specified.
        """
        ...

    def dbError(self, e: java.io.IOException) -> None: ...

    def deleteAddressRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Removes the block of defined bytes from the listing. All necessary checks will be made by 
         listing before this method is called, so just do the work.
        @param start the first address in the range.
        @param end the last address in the range.
        @param monitor the TaskMonitor that tracks progress and is used to tell if the user cancels 
         the operation.
        @throws CancelledException if the user cancels the operation.
        """
        ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fallThroughChanged(self, fromAddr: ghidra.program.model.address.Address, newFallThroughRef: ghidra.program.model.symbol.Reference) -> None:
        """
        Callback from ReferenceManager when a new fall-through reference is set.
        @param fromAddr fall-through from location
        @param newFallThroughRef new fallthrough reference or null if removed
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeUnitAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the next code unit whose min address is greater than the specified address.
        @param addr the address to look after
        @return CodeUnit the code unit after the specified address, or null if a code unit does not 
         exist
        """
        ...

    def getCodeUnitAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the code unit whose min address equals the specified address.
        @param address the min address of the code unit to return
        @return CodeUnit the code unit at the specified address, or null if a code unit does not 
         exist
        """
        ...

    def getCodeUnitBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the next code unit whose min address is closest to and less than the specified 
         address.
        @param address the address to look before
        @return CodeUnit the code unit before the specified address, or null if a code unit does not 
         exist
        """
        ...

    def getCodeUnitContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the code unit whose min address is less than or equal to the specified address and 
         whose max address is greater than or equal to the specified address.
         <pre>{@literal
         codeunit.minAddress() <= addr <= codeunit.maxAddress()
         }</pre>
        @param address the address for which to find the code containing it.
        @return CodeUnit the code unit containing the specified address, or null if a code unit does 
         not exist.
        """
        ...

    @overload
    def getCodeUnitIterator(self, property: unicode, address: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Get an iterator that contains the code units which have the specified property type defined. 
         Only code units at an address greater than or equal to the specified start address will be 
         returned by the iterator. If the start address is null then check the entire program.
         <P>
         Standard property types are defined in the CodeUnit class.  The property types are:
                  <ul>
                      <li>COMMENT_PROPERTY</li>
                      <li>INSTRUCTION_PROPERTY</li>
                      <li>DEFINED_DATA_PROPERTY</li>
                  </ul>
         Property types can also be user defined.
        @param property the name of the user defined property type or special standard name from 
         above.
        @param address the address to start the iterator, or null to iterator the entire program
        @param forward true means get iterator in the forward direction
        @return a CodeUnitIterator that returns all code units from the indicated start address that 
         have the specified property type defined.
        """
        ...

    @overload
    def getCodeUnitIterator(self, property: unicode, addrSetView: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Get an iterator that contains the code units which have the specified property type defined. 
         Only code units starting within the address set specified will be returned by the iterator.
         If the address set is null then check the entire program.
         <br>
         Standard property types are defined in the CodeUnit class.  The property types are:
                  <ul>
                      <li>REFERENCE_PROPERTY</li>
                      <li>INSTRUCTION_PROPERTY</li>
                      <li>DEFINED_DATA_PROPERTY</li>
                  </ul>
         Property types can also be user defined.
        @param property the name of the property type, or this can be user defined.
        @param addrSetView the address set to iterate, or null to iterate over the entire program
        @param forward true means the iterator is in the forward direction
        @return a CodeUnitIterator that returns all code units from the indicated address set that 
         have the specified property type defined.
        """
        ...

    @overload
    def getCodeUnits(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Returns an iterator over all codeUnits in the program from the given start address to either 
         the end address or the start address, depending if the iterator is forward or not.
        @param start the starting address for the iterator.
        @param forward if true the iterator returns all codeUnits from the given start address to 
         the end of the program, otherwise it returns all codeUnits from the given start address to 
         the start of the program.
        @return code unit iterator
        """
        ...

    @overload
    def getCodeUnits(self, set: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Returns an iterator over all codeUnits in the given addressSet. The iterator will go from 
         the lowest address to the largest or from the largest to the lowest depending on the forward 
         parameter.
        @param set the memory address set over which code units should be iterated (required)
        @param forward determines if the iterator goes from lowest address to highest or the other
         way around.
        @return code unit iterator
        """
        ...

    def getComment(self, commentType: int, address: ghidra.program.model.address.Address) -> unicode:
        """
        Get the comment for the given type at the specified address.
        @param commentType either EOL_COMMENT, PRE_COMMENT, POST_COMMENT, PLATE_COMMENT, or 
         REPEATABLE_COMMENT
        @param address the address of the comment.
        @return the comment string of the appropriate type or null if no comment of that type exists 
         for this code unit
        @throws IllegalArgumentException if type is not one of the types of comments supported
        """
        ...

    @overload
    def getCommentAddressIterator(self, addrSet: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Get an iterator over addresses that have comments of any type.
        @param addrSet address set containing the comment addresses to iterate over.
        @param forward true to iterate in the direction of increasing addresses.
        @return the iterator
        """
        ...

    @overload
    def getCommentAddressIterator(self, commentType: int, set: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.address.AddressIterator:
        """
        Get a forward iterator over addresses that have comments of the given type.
        @param commentType comment type defined in CodeUnit
        @param set address set (null for all defined memory)
        @param forward true to iterate in the direction of increasing addresses.
        @return address iterator
        """
        ...

    def getCommentCodeUnitIterator(self, commentType: int, set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.listing.CodeUnitIterator:
        """
        Get a forward iterator over code units that have comments of the given type.
        @param commentType comment type defined in CodeUnit
        @param set address set (null for all defined memory)
        @return code unit iterator
        """
        ...

    def getCommentHistory(self, addr: ghidra.program.model.address.Address, commentType: int) -> List[ghidra.program.model.listing.CommentHistory]:
        """
        Get the comment history for the comment type at the given address
        @param addr address for the comment history
        @param commentType comment type
        @return zero length array if no history exists
        """
        ...

    @overload
    def getCompositeData(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.DataIterator:
        """
        Returns a composite data iterator beginning at the specified start address.
        @param start the address to begin iterator
        @param forward true means get iterator in forward direction
        @return the composite data iterator
        """
        ...

    @overload
    def getCompositeData(self, addrSet: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.DataIterator:
        """
        Returns a composite data iterator limited to the addresses in the specified address set.
        @param addrSet the address set to limit the iterator
        @param forward determines if the iterator will go from the lowest address to the highest or 
         the other way around.
        @return DataIterator the composite data iterator
        """
        ...

    @overload
    def getData(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all data in the program from the given start address to either the 
         end address or the start address, depending if the iterator is forward or not.
        @param start the starting address for the iterator.
        @param forward if true the iterator returns all data from the given start address to the end 
         of the program, otherwise it returns all data from the given start address to the start of 
         the program.
        @return the iterator
        """
        ...

    @overload
    def getData(self, set: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all data in the given addressSet. The iterator will go from the 
         lowest address to the largest or from the largest to the lowest depending on the forward 
         parameter.
        @param set restrict the returned instructions to these addresses
        @param forward determines if the iterator goes from lowest address to highest or the other 
         way around.
        @return the iterator
        """
        ...

    def getDataAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next data whose min address is greater than the specified address.
        @param addr the address to look after
        @return the data after the specified address, or null if a data does not exist
        """
        ...

    def getDataAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the data whose min address equals the specified address.
        @param address the min address of the data to return
        @return the data at the specified address, or null if data does not exist
        """
        ...

    def getDataBefore(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next data whose min address is closest to and less than the specified address.
        @param addr the address to look before
        @return the data before the specified address, or null if a data does not exist
        """
        ...

    def getDataContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the data whose min address is less than or equal to the specified address and whose 
         max address is greater than or equal to the specified address.
         <pre>{@literal
         data.minAddress() <= addr <= data.maxAddress()
         }</pre>
        @param addr the address to be contained
        @return the data containing the specified address, or null if a data does not exist that 
         starts at that address.
        """
        ...

    @overload
    def getDefinedData(self, address: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all defined data in the program from the given start address to 
         either the end address or the start address, depending if the iterator is forward or not.
        @param address the starting address for the iterator.
        @param forward if true the iterator returns all defined data from the given start address to 
         the end of the program, otherwise it returns all defined data from the given start address 
         to the start of the program.
        @return the iterator
        """
        ...

    @overload
    def getDefinedData(self, set: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.DataIterator:
        """
        Returns an iterator over all defined data in the given addressSet. The iterator will go from 
         the lowest address to the largest or from the largest to the lowest depending on the forward 
         parameter.
        @param set restrict the returned instructions to these addresses
        @param forward determines if the iterator goes from lowest address to highest or the other 
         way around.
        @return the iterator
        """
        ...

    def getDefinedDataAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next defined data whose min address is greater than the specified address.
        @param addr the address to look after
        @return the defined data after the specified address, null if a defined data does not exist
        """
        ...

    def getDefinedDataAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data whose min address equals the specified address.
        @param address the min address of the data defined to return
        @return the defined data at the specified address, or null if a defined data does 
         not exist
        """
        ...

    def getDefinedDataBefore(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the next defined data whose min address is closest to and less than the specified 
         address.
        @param addr the address to look before
        @return the defined data before the specified address, null if a defined data does not exist
        """
        ...

    def getDefinedDataContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data whose min address is less than or equal to the specified address 
         and whose max address is greater than or equal to the specified address.
         <pre>{@literal
         data.minAddress() <= addr <= data.maxAddress()
         }</pre>
        @param addr the address to be contained
        @return the defined data containing the address, null if a defined data does not exist
        """
        ...

    def getFirstUndefinedData(self, set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Data:
        """
        Returns the next undefined data whose min address falls within the address set searching in 
         the forward direction {@code (e.g., 0 -> 0xfff).}
        @param set the address set to look within (required).
        @param monitor the current monitor.
        @return the first undefined data within the address set, or null if there is none.
        """
        ...

    def getFirstUndefinedDataAfter(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Data:
        """
        Returns the next undefined data whose min address is greater than the specified address.
        @param addr the address to look after
        @param monitor the task monitor
        @return Data the undefined data after the address, null if a undefined data does not exist
        """
        ...

    def getFirstUndefinedDataBefore(self, addr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Data:
        """
        Returns the next undefined data whose min address is closest to and less than the specified 
         address.
        @param addr the address to look before
        @param monitor the task monitor
        @return the undefined data before the address, null if a undefined data does not exist
        """
        ...

    def getInstructionAfter(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the next instruction whose min address is greater than the specified address.
        @param addr the address to look after
        @return the instruction after the specified address, or null if a instruction 
         does not exist
        """
        ...

    def getInstructionAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction whose min address equals the specified address or null if the 
         address is not the beginning address of some code unit.
        @param address the min address of the instruction to return
        @return the instruction at the specified address, or null if a instruction does not 
         exist starting at the given address.
        """
        ...

    def getInstructionBefore(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the next instruction whose min address is closest to and less than the specified 
         address.
        @param addr the address to look before
        @return the instruction before the specified address, or null if a instruction 
         does not exist
        """
        ...

    def getInstructionContaining(self, address: ghidra.program.model.address.Address, usePrototypeLength: bool) -> ghidra.program.model.listing.Instruction:
        """
        Returns an instruction whose min address is less than or equal to the specified address and 
         whose max address is greater than or equal to the specified address.
         If {@code usePrototypeLength==true}
         <pre>{@literal
         instruction.getMinAddress() <= addr <= 
            instruction.getMinAddress().add(instruction.getPrototype().getLength() - 1)
         }</pre>
         If {@code usePrototypeLength==false}
         <pre>{@literal
            instruction.getMinAddress() <= addr <= instruction.getMaxAddress()
         }</pre>
         The use of the prototype length is required when guarding against memory modifications.  If
         a length-override is present only one of the entangled instructions will be returned and is
         intended to simply indicate the presence of a conflict.
        @param address the address to be contained
        @param usePrototypeLength if actual prototype length should be considered when identifying a 
         conflict (required when checking for memory modification conflicts), otherwise code unit
         length is used.  These lengths can vary when a
         {@link Instruction#setLengthOverride(int) length-override} is in affect for an instruction.
        @return the instruction containing the specified address, or null if a 
         instruction does not exist
        """
        ...

    @overload
    def getInstructions(self, address: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.InstructionIterator:
        """
        Returns an iterator over all instructions in the program from the given start address to 
         either the end address or the start address, depending if the iterator is forward or not.
        @param address the starting address for the iterator.
        @param forward if true the iterator returns all instructions from the given start address to 
         the end of the program, otherwise it returns all instructions from the given start address 
         to the start of the program.
        @return the iterator
        """
        ...

    @overload
    def getInstructions(self, set: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.InstructionIterator:
        """
        Returns an iterator over all instructions in the given addressSet. The iterator will go from 
         the lowest address to the largest or from the largest to the lowest depending on the forward 
         parameter.
        @param set restrict the returned instructions to these addresses
        @param forward determines if the iterator goes from lowest address to highest or the other 
         way around.
        @return the iterator
        """
        ...

    def getNumDefinedData(self) -> int:
        """
        Returns the number of defined data in the program.
        @return the number of defined data in the program.
        """
        ...

    def getNumInstructions(self) -> int:
        """
        Returns the number of instructions in the program.
        @return the number of instructions in the program.
        """
        ...

    def getPropertyMap(self, propertyName: unicode) -> ghidra.program.model.util.PropertyMap:
        """
        Returns the property map object that is associated with the specified property name.
        @param propertyName the name of the property
        @return the property map object associated to the property name
        """
        ...

    def getReferenceMgr(self) -> ghidra.program.model.symbol.ReferenceManager:
        """
        Returns the reference manager being used by this code manager.
        @return ReferenceManager the reference manager being used by this code manager
        """
        ...

    def getUndefinedAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the undefined data whose min address equals the specified address.
        @param address the min address of the undefined data to return
        @return Data the undefined data at the address, null if undefined data does not exist
        """
        ...

    def getUndefinedRanges(self, set: ghidra.program.model.address.AddressSetView, initializedMemoryOnly: bool, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView: ...

    def getUserDefinedProperties(self) -> Iterator[unicode]:
        """
        Returns an iterator over all user-defined properties.
        @return Iterator an iterator over all user-defined properties
        """
        ...

    def hashCode(self) -> int: ...

    def invalidateCache(self, all: bool) -> None: ...

    def invalidateCodeUnitCache(self) -> None:
        """
        Invalidates the cache for the code units.
        """
        ...

    def isUndefined(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool:
        """
        Checks if all the addresses from start to end have undefined data.
        @param start the first address in the range to check.
        @param end the last address in the range to check.
        @return true if all the addresses in the range have undefined data.
        """
        ...

    def memoryChanged(self, addr: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Notification that memory has changed, so clear the cache for the affected code units.
        @param addr start of change
        @param end end address of change
        """
        ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: long, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Move a block of code from one address to a new address.
         <P>
         Updates all property managers, symbols, and references.
        @param fromAddr the first address in the range to be moved.
        @param toAddr the address to move to.
        @param length the number of addresses to move.
        @param monitor the TaskMonitor that tracks progress and is used to tell if the user cancels 
         the operation.
        @throws CancelledException if the user cancels the operation.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def programReady(self, openMode: int, currentRevision: int, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def reDisassembleAllInstructions(self, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Complete language transformation of all instructions.  All existing prototypes will be 
         discarded and all instructions re-disassembled following flow and adjusting context as 
         needed. Instructions which fail to re-disassemble will be marked - since only one byte will 
         be skipped, such bad instruction disassembly may cause subsequent errors due to possible 
         instruction shift.
         <P>
         This method is only intended for use by the ProgramDB setLanguage method which must ensure 
         that the context has been properly initialized.
        @param monitor task monitor
        @throws IOException if IO error occurs
        @throws CancelledException if the operation is canceled.
        """
        ...

    def removeUserDefinedProperty(self, propertyName: unicode) -> None:
        """
        Removes the user-defined property with the specified property name.
        @param propertyName the name of the user-defined property to remove
        """
        ...

    def replaceDataTypes(self, oldDataTypeID: long, newDataTypeID: long) -> None: ...

    def setComment(self, address: ghidra.program.model.address.Address, commentType: int, comment: unicode) -> None:
        """
        Set the comment for the given comment type at the specified address.
        @param address the address of the comment.
        @param commentType either EOL_COMMENT, PRE_COMMENT, POST_COMMENT, PLATE_COMMENT, or 
         REPEATABLE_COMMENT
        @param comment comment to set at the address
        @throws IllegalArgumentException if type is not one of the types of comments supported
        """
        ...

    def setProgram(self, program: ghidra.program.database.ProgramDB) -> None:
        """
        Set the program after all the managers have been created.
        @param program The program object that this manager belongs to.
        """
        ...

    def toString(self) -> unicode: ...

    def updateDataReferences(self, data: ghidra.program.model.listing.Data) -> None:
        """
        Update the data references on this data item. Get rid of any references first, then add in 
         any new ones.
        @param data the data object to be updated
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def numDefinedData(self) -> int: ...

    @property
    def numInstructions(self) -> int: ...

    @property
    def program(self) -> None: ...  # No getter available.

    @program.setter
    def program(self, value: ghidra.program.database.ProgramDB) -> None: ...

    @property
    def referenceMgr(self) -> ghidra.program.model.symbol.ReferenceManager: ...

    @property
    def userDefinedProperties(self) -> java.util.Iterator: ...
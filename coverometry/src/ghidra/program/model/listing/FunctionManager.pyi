from typing import Iterator
import ghidra.program.database
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang
import java.util


class FunctionManager(ghidra.program.database.ManagerDB, object):
    """
    The manager for functions
    """









    @overload
    def createFunction(self, name: unicode, entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Function:
        """
        Create a function with the given body at entry point within the global namespace.
        @param name the name of the new function or null for default name
        @param entryPoint entry point of function
        @param body addresses contained in the function body
        @param source the source of this function
        @return new function or null if one or more functions overlap the specified body address set.
        @throws InvalidInputException if the name has invalid characters
        @throws OverlappingFunctionException if the address set of the body overlaps an existing
                     function
        """
        ...

    @overload
    def createFunction(self, name: unicode, nameSpace: ghidra.program.model.symbol.Namespace, entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Function:
        """
        Create a function with the given body at entry point.
        @param name the name of the new function or null for default name
        @param nameSpace the nameSpace in which to create the function
        @param entryPoint entry point of function
        @param body addresses contained in the function body
        @param source the source of this function
        @return new function or null if one or more functions overlap the specified body address set.
        @throws InvalidInputException if the name has invalid characters
        @throws OverlappingFunctionException if the address set of the body overlaps an existing
                     function
        """
        ...

    def createThunkFunction(self, name: unicode, nameSpace: ghidra.program.model.symbol.Namespace, entryPoint: ghidra.program.model.address.Address, body: ghidra.program.model.address.AddressSetView, thunkedFunction: ghidra.program.model.listing.Function, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Function:
        """
        Create a thunk function with the given body at entry point.
        @param name the name of the new function or null for default name
        @param nameSpace the nameSpace in which to create the function
        @param entryPoint entry point of function
        @param body addresses contained in the function body
        @param thunkedFunction referenced function (required is creating a thunk function)
        @param source the source of this function
        @return new function or null if one or more functions overlap the specified body address set.
        @throws OverlappingFunctionException if the address set of the body overlaps an existing
                     function
        """
        ...

    def deleteAddressRange(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address, __a2: ghidra.util.task.TaskMonitor) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getCallingConvention(self, name: unicode) -> ghidra.program.model.lang.PrototypeModel:
        """
        Gets the prototype model of the calling convention with the specified name in this program
        @param name the calling convention name
        @return the named function calling convention prototype model or null.
        """
        ...

    def getCallingConventionNames(self) -> java.util.Collection:
        """
        Get the ordered list of defined calling convention names.  The reserved names 
         "unknown" and "default" are not included.  The returned collection may not include all names 
         referenced by various functions and function-definitions.  This set is limited to those
         defined by the associated compiler specification.  
         See {@link DataTypeManager#getDefinedCallingConventionNames}.
         <p>
         For a set of all known names (including those that are not defined by compiler spec)
         see {@link DataTypeManager#getKnownCallingConventionNames()}.
        @return the calling convention names.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        Gets the default calling convention's prototype model in this program.
        @return the default calling convention prototype model or null.
        """
        ...

    def getExternalFunctions(self) -> ghidra.program.model.listing.FunctionIterator:
        """
        Get an iterator over all external functions. Functions returned have no particular order.
        @return an iterator over external functions
        """
        ...

    def getFunction(self, key: long) -> ghidra.program.model.listing.Function:
        """
        Get a Function object by its key
        @param key function symbol key
        @return function object or null if not found
        """
        ...

    def getFunctionAt(self, entryPoint: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Get the function at entryPoint
        @param entryPoint the entry point
        @return null if there is no function at entryPoint
        """
        ...

    def getFunctionContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Get a function containing an address.
        @param addr address within the function
        @return function containing this address, null otherwise
        """
        ...

    def getFunctionCount(self) -> int:
        """
        Returns the total number of functions in the program including external functions
        @return the count
        """
        ...

    def getFunctionTagManager(self) -> ghidra.program.model.listing.FunctionTagManager:
        """
        Returns the function tag manager
        @return the function tag manager
        """
        ...

    @overload
    def getFunctions(self, forward: bool) -> ghidra.program.model.listing.FunctionIterator:
        """
        Returns an iterator over all non-external functions in address (entry point) order
        @param forward true means to iterate in ascending address order
        @return the iterator
        """
        ...

    @overload
    def getFunctions(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.FunctionIterator:
        """
        Get an iterator over non-external functions starting at an address and ordered by entry
         address
        @param start starting address
        @param forward true means to iterate in ascending address order
        @return an iterator over functions.
        """
        ...

    @overload
    def getFunctions(self, asv: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.FunctionIterator:
        """
        Get an iterator over functions with entry points in the specified address set. Function are
         ordered based upon entry address.
        @param asv address set to iterate over
        @param forward true means to iterate in ascending address order
        @return an iterator over functions.
        """
        ...

    @overload
    def getFunctionsNoStubs(self, forward: bool) -> ghidra.program.model.listing.FunctionIterator:
        """
        Returns an iterator over all REAL functions in address (entry point) order (real functions
         have instructions, and aren't stubs)
        @param forward true means to iterate in ascending address order
        @return the iterator
        """
        ...

    @overload
    def getFunctionsNoStubs(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.listing.FunctionIterator:
        """
        Get an iterator over REAL functions starting at an address and ordered by entry address (real
         functions have instructions, and aren't stubs).
        @param start starting address
        @param forward true means to iterate in ascending address order
        @return an iterator over functions.
        """
        ...

    @overload
    def getFunctionsNoStubs(self, asv: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.listing.FunctionIterator:
        """
        Get an iterator over REAL functions with entry points in the specified address set (real
         functions have instructions, and aren't stubs). Functions are ordered based upon entry
         address.
        @param asv address set to iterate over
        @param forward true means to iterate in ascending address order
        @return an iterator over functions.
        """
        ...

    def getFunctionsOverlapping(self, set: ghidra.program.model.address.AddressSetView) -> Iterator[ghidra.program.model.listing.Function]:
        """
        Return an iterator over functions that overlap the given address set.
        @param set address set of interest
        @return iterator over Functions
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns this manager's program
        @return the program
        """
        ...

    def getReferencedFunction(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Get the function which resides at the specified address or is referenced from the specified 
         address
        @param address function address or address of pointer to a function.
        @return referenced function or null
        """
        ...

    def getReferencedVariable(self, instrAddr: ghidra.program.model.address.Address, storageAddr: ghidra.program.model.address.Address, size: int, isRead: bool) -> ghidra.program.model.listing.Variable:
        """
        Attempts to determine which if any of the local functions variables are referenced by the
         specified reference. In utilizing the firstUseOffset scoping model, negative offsets
         (relative to the functions entry) are shifted beyond the maximum positive offset within the
         function. While this does not account for the actual instruction flow, it is hopefully
         accurate enough for most situations.
        @param instrAddr the instruction address
        @param storageAddr the storage address
        @param size varnode size in bytes (1 is assumed if value &lt;= 0)
        @param isRead true if the reference is a read reference
        @return referenced variable or null if one not found
        """
        ...

    def hashCode(self) -> int: ...

    def invalidateCache(self, all: bool) -> None:
        """
        Clears all data caches
        @param all if false, some managers may not need to update their cache if they can
         tell that its not necessary.  If this flag is true, then all managers should clear
         their cache no matter what.
        """
        ...

    def isInFunction(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if this address contains a function.
        @param addr address to check
        @return true if this address is contained in a function.
        """
        ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: long, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Move all objects within an address range to a new location
        @param fromAddr the first address of the range to be moved
        @param toAddr the address where to the range is to be moved
        @param length the number of addresses to move
        @param monitor the task monitor to use in any upgrade operations
        @throws CancelledException if the user cancelled the operation via the task monitor
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def programReady(self, __a0: int, __a1: int, __a2: ghidra.util.task.TaskMonitor) -> None: ...

    def removeFunction(self, entryPoint: ghidra.program.model.address.Address) -> bool:
        """
        Remove a function defined at entryPoint
        @param entryPoint the entry point
        @return true if the function was removed
        """
        ...

    def setProgram(self, __a0: ghidra.program.database.ProgramDB) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def callingConventionNames(self) -> java.util.Collection: ...

    @property
    def defaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def externalFunctions(self) -> ghidra.program.model.listing.FunctionIterator: ...

    @property
    def functionCount(self) -> int: ...

    @property
    def functionTagManager(self) -> ghidra.program.model.listing.FunctionTagManager: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...
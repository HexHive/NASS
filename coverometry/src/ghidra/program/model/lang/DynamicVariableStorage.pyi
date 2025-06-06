from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import java.lang


class DynamicVariableStorage(ghidra.program.model.listing.VariableStorage):




    @overload
    def __init__(self, program: ghidra.program.model.lang.ProgramArchitecture, forcedIndirect: bool, varnodes: List[ghidra.program.model.pcode.Varnode]):
        """
        Construct dynamic variable storage
        @param program
        @param forcedIndirect if true indicates that the parameter has been forced to pass 
         as a pointer instead of its raw type
        @param varnodes one or more ordered storage varnodes
        @throws InvalidInputException if specified varnodes violate storage restrictions
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.lang.ProgramArchitecture, autoParamType: ghidra.program.model.listing.AutoParameterType, varnodes: List[ghidra.program.model.pcode.Varnode]):
        """
        Construct dynamic variable storage with an optional auto-parameter type
        @param program
        @param autoParamType auto-parameter type or null if not applicable
        @param varnodes one or more ordered storage varnodes
        @throws InvalidInputException if specified varnodes violate storage restrictions
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.lang.ProgramArchitecture, forcedIndirect: bool, address: ghidra.program.model.address.Address, size: int):
        """
        Construct dynamic variable storage
        @param program
        @param forcedIndirect if true indicates that the parameter has been forced to pass 
         as a pointer instead of its raw type
        @param address varnode address
        @param size varnode size
        @throws InvalidInputException
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.lang.ProgramArchitecture, autoParamType: ghidra.program.model.listing.AutoParameterType, address: ghidra.program.model.address.Address, size: int):
        """
        Construct dynamic variable storage with an optional auto-parameter type
        @param program
        @param autoParamType auto-parameter type or null if not applicable
        @param address varnode address
        @param size varnode size
        @throws InvalidInputException
        """
        ...



    def clone(self, newProgramArch: ghidra.program.model.lang.ProgramArchitecture) -> ghidra.program.model.listing.VariableStorage:
        """
        Attempt to clone variable storage for use in a different program.
         Dynamic storage characteristics will not be preserved.
        @param newProgramArch target program architecture details
        @return cloned storage
        @throws InvalidInputException if specified varnodes violate storage restrictions
        """
        ...

    @overload
    def compareTo(self, otherStorage: ghidra.program.model.listing.VariableStorage) -> int:
        """
        Compare this variable storage with another.  A value of 0 indicates 
         that the two objects are equal
        @see java.lang.Comparable#compareTo(java.lang.Object)
        """
        ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def contains(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the specified address is contained within this storage
        @param address address
        @return true if this storage varnode(s) contain specified address
        """
        ...

    @staticmethod
    def deserialize(programArch: ghidra.program.model.lang.ProgramArchitecture, serialization: unicode) -> ghidra.program.model.listing.VariableStorage:
        """
        Construct variable storage
        @param programArch program architecture details
        @param serialization storage serialization string
        @return deserialized variable storage.  {@link #BAD_STORAGE} may be returned on failure.
        @throws InvalidInputException if specified varnodes violate storage restrictions
        """
        ...

    def equals(self, obj: object) -> bool:
        """
        This storage is considered equal if it consists of the same storage varnodes.
        """
        ...

    def getAutoParameterType(self) -> ghidra.program.model.listing.AutoParameterType: ...

    def getClass(self) -> java.lang.Class: ...

    def getFirstVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        @return first varnode within the ordered list of varnodes
        """
        ...

    def getLastVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        @return last varnode within the ordered list of varnodes
        """
        ...

    def getLongHash(self) -> long: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        """
        @return the minimum address corresponding to the first varnode of this storage
         or null if this is a special empty storage: {@link #isBadStorage()}, {@link #isUnassignedStorage()},
         {@link #isVoidStorage()}
        """
        ...

    def getProgramArchitecture(self) -> ghidra.program.model.lang.ProgramArchitecture:
        """
        @return program for which this storage is associated
        """
        ...

    def getRegister(self) -> ghidra.program.model.lang.Register:
        """
        @return first storage register associated with this register or compound storage, else
         null is returned.
        @see Variable#isRegisterVariable()
        """
        ...

    def getRegisters(self) -> List[ghidra.program.model.lang.Register]:
        """
        @return storage register(s) associated with this register or compound storage, else
         null is returned.
        @see Variable#isRegisterVariable()
        @see #isCompoundStorage()
        """
        ...

    @overload
    def getSerializationString(self) -> unicode:
        """
        Return a serialization form of this variable storage.
        @return storage serialization string useful for subsequent reconstruction
        """
        ...

    @overload
    @staticmethod
    def getSerializationString(varnodes: List[ghidra.program.model.pcode.Varnode]) -> unicode:
        """
        Generate VariableStorage serialization string
        @param varnodes one or more storage varnodes
        @return storage serialization string useful for subsequent reconstruction
         of a VariableStorage object
        """
        ...

    def getStackOffset(self) -> int:
        """
        @return the stack offset associated with simple stack storage or compound 
         storage where the last varnode is stack, see {@link #hasStackStorage()}.
        @throws UnsupportedOperationException if storage does not have a stack varnode
        """
        ...

    @overload
    @staticmethod
    def getUnassignedDynamicStorage(forcedIndirect: bool) -> ghidra.program.model.lang.DynamicVariableStorage:
        """
        Construct Unassigned dynamic variable storage.
         NOTE: The {@link #isUnassignedStorage()} method should be used to
         detect this type of storage.
        @param forcedIndirect if true indicates that the parameter has been forced to pass 
         as a pointer instead of its raw type
        """
        ...

    @overload
    @staticmethod
    def getUnassignedDynamicStorage(autoParamType: ghidra.program.model.listing.AutoParameterType) -> ghidra.program.model.lang.DynamicVariableStorage:
        """
        Construct Unassigned dynamic variable storage with an optional auto-parameter type.
         NOTE: The {@link #isUnassignedStorage()} method should be used to
         detect this type of storage.
        @param autoParamType auto-parameter type or null if not applicable
        """
        ...

    def getVarnodeCount(self) -> int:
        """
        @return the number of varnodes associated with this variable storage
        """
        ...

    @overload
    def getVarnodes(self) -> List[ghidra.program.model.pcode.Varnode]:
        """
        @return ordered varnodes associated with this variable storage
        """
        ...

    @overload
    @staticmethod
    def getVarnodes(addrFactory: ghidra.program.model.address.AddressFactory, serialization: unicode) -> List[ghidra.program.model.pcode.Varnode]:
        """
        Parse a storage serialization string to produce an array or varnodes
        @param addrFactory address factory
        @param serialization serialized variable storage string (see {@link #getSerializationString()}).
        @return array of varnodes or null if invalid
        @throws InvalidInputException if specified registers violate storage restrictions
        """
        ...

    def hasStackStorage(self) -> bool:
        """
        @return true if the last varnode for simple or compound storage is a stack varnode
        """
        ...

    def hashCode(self) -> int: ...

    @overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Determine if this storage intersects the specified address set
        @param set address set
        @return true if this storage intersects the specified address set
        """
        ...

    @overload
    def intersects(self, reg: ghidra.program.model.lang.Register) -> bool:
        """
        Determine if this storage intersects the specified register
        @param reg the register
        @return true if this storage intersects the specified register
        """
        ...

    @overload
    def intersects(self, variableStorage: ghidra.program.model.listing.VariableStorage) -> bool:
        """
        Determine if this variable storage intersects the specified variable storage
        @param variableStorage other variable storage
        @return true if any intersection exists between this storage and the specified
         variable storage
        """
        ...

    def isAutoStorage(self) -> bool: ...

    def isBadStorage(self) -> bool:
        """
        @return true if this storage is bad (could not be resolved)
        """
        ...

    def isCompoundStorage(self) -> bool:
        """
        @return true if storage consists of two or more storage varnodes
        """
        ...

    def isConstantStorage(self) -> bool:
        """
        @return true if storage consists of a single constant-space varnode which is used when storing
         local function constants.
        """
        ...

    def isForcedIndirect(self) -> bool: ...

    def isHashStorage(self) -> bool:
        """
        @return true if storage consists of a single hash-space varnode which is used when storing
         local unique function variables.
        """
        ...

    def isMemoryStorage(self) -> bool:
        """
        @return true if storage consists of a single memory varnode which does not correspond
         to a register.
        """
        ...

    def isRegisterStorage(self) -> bool:
        """
        @return true if this is a simple variable consisting of a single register varnode
         which will be returned by either the {@link Variable#getFirstStorageVarnode()} or 
         {@link Variable#getLastStorageVarnode()} methods.  The register can be obtained using the 
         {@link #getRegister()} method.  Keep in mind that registers
         may exist in a memory space or the register space.
        """
        ...

    def isStackStorage(self) -> bool:
        """
        @return true if storage consists of a single stack varnode
        """
        ...

    def isUnassignedStorage(self) -> bool: ...

    def isUniqueStorage(self) -> bool:
        """
        @return true if storage consists of a single unique-space varnode which is used during
         function analysis.  This type of storage is not suitable for database-stored function
         variables.  This type of storage must be properly converted to Hash storage when 
         storing unique function variables.
        """
        ...

    def isValid(self) -> bool:
        """
        @return true if storage is assigned and is not BAD
        """
        ...

    def isVoidStorage(self) -> bool:
        """
        @return true if storage corresponds to the VOID_STORAGE instance
        @see #VOID_STORAGE
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def size(self) -> int:
        """
        @return the total size of corresponding storage varnodes
        """
        ...

    def toString(self) -> unicode: ...

    @staticmethod
    def translateSerialization(translator: ghidra.program.util.LanguageTranslator, serialization: unicode) -> unicode:
        """
        Perform language translations on VariableStorage serialization string
        @param translator language translator
        @param serialization VariableStorage serialization string
        @return translated serialization string
        @throws InvalidInputException if serialization has invalid format
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def autoParameterType(self) -> ghidra.program.model.listing.AutoParameterType: ...

    @property
    def autoStorage(self) -> bool: ...

    @property
    def forcedIndirect(self) -> bool: ...

    @property
    def unassignedStorage(self) -> bool: ...
from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import java.lang


class VarnodeContext(object, ghidra.program.model.lang.ProcessorContext):
    BAD_ADDRESS: ghidra.program.model.address.Address
    BAD_SPACE_ID_VALUE: int
    SUSPECT_ZERO_ADDRESS: ghidra.program.model.address.Address
    debug: bool



    def __init__(self, program: ghidra.program.model.listing.Program, programContext: ghidra.program.model.listing.ProgramContext, spaceProgramContext: ghidra.program.model.listing.ProgramContext): ...



    def add(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        """
        Add two varnodes together to get a new value
         This could create a new space and return a varnode pointed into that space
        @param val1 first value
        @param val2 second value
        @return varnode that could be a constant, or an offset into a space
        @throws NotFoundException if any constant is needed not known
        """
        ...

    def and(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode: ...

    def clearReadExecutableCode(self) -> None: ...

    def clearRegister(self, reg: ghidra.program.model.lang.Register) -> None: ...

    def copy(self, out: ghidra.program.model.pcode.Varnode, in_: ghidra.program.model.pcode.Varnode, mustClearAll: bool, evaluator: ghidra.program.util.ContextEvaluator) -> None:
        """
        Copy the varnode with as little manipulation as possible.
         Try to keep whatever partial state there is intact if a real value isn't required.
        @param out varnode to put it in
        @param in varnode to copy from.
        @param mustClearAll true if must clear if value is not unique
        @param evaluator user provided evaluator if needed
        @throws NotFoundException if there is no known value for in
        """
        ...

    def copyToFutureFlowState(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address) -> None: ...

    def createBadVarnode(self) -> ghidra.program.model.pcode.Varnode: ...

    def createConstantVarnode(self, value: long, size: int) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    def createVarnode(self, value: long, spaceID: int, size: int) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    def createVarnode(self, bigVal: long, spaceVal: long, size: int) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    @staticmethod
    def dumpContextValue(__a0: ghidra.program.model.lang.RegisterValue, __a1: unicode) -> unicode: ...

    @overload
    @staticmethod
    def dumpContextValue(__a0: ghidra.program.model.lang.RegisterValue, __a1: unicode, __a2: java.lang.StringBuilder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def extendValue(self, out: ghidra.program.model.pcode.Varnode, in_: List[ghidra.program.model.pcode.Varnode], signExtend: bool, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        """
        Extend a constant value if it can be extended.
        @param out varnode to extend into (for size)
        @param in varnode value to extend the size
        @return 
        @throws NotFoundException
        """
        ...

    def flowEnd(self, address: ghidra.program.model.address.Address) -> None: ...

    def flowStart(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address) -> None: ...

    def flowToAddress(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address) -> None: ...

    def getAddressSpace(self, name: unicode) -> int: ...

    def getBaseContextRegister(self) -> ghidra.program.model.lang.Register: ...

    def getClass(self) -> java.lang.Class: ...

    def getConstant(self, vnode: ghidra.program.model.pcode.Varnode, evaluator: ghidra.program.util.ContextEvaluator) -> long: ...

    def getCurrentInstruction(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction: ...

    def getDebug(self) -> bool: ...

    def getKilledVarnodes(self, targetFunc: ghidra.program.model.listing.Function) -> List[ghidra.program.model.pcode.Varnode]:
        """
        @param targetFunc function to get killed varnodes for
 
         NOTE: this removes the return varnodes so they aren't duplicated
        @return varnode that represents where functions place their return value
        """
        ...

    def getKnownFlowToAddresses(self, toAddr: ghidra.program.model.address.Address) -> List[ghidra.program.model.address.Address]: ...

    @overload
    def getLastSetLocation(self, reg: ghidra.program.model.lang.Register, bval: long) -> ghidra.program.model.address.Address:
        """
        return the location that this register was last set
         This is a transient thing, so it should only be used as a particular flow is being processed...
        @param reg register to find last set location
        @param bval value to look for to differentiate set locations, null if don't care
        @return address that the register was set.
        """
        ...

    @overload
    def getLastSetLocation(self, rvar: ghidra.program.model.pcode.Varnode, bval: long) -> ghidra.program.model.address.Address:
        """
        return the location that this varnode was last set
         This is a transient thing, so it should only be used as a particular flow is being processed...
        @param rvar the register varnode
        @param bval this parameter is unused.
        @return address that the register was set.
        """
        ...

    @overload
    def getRegister(self, name: unicode) -> ghidra.program.model.lang.Register: ...

    @overload
    def getRegister(self, vnode: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.lang.Register:
        """
        Return a register given a varnode
        """
        ...

    @overload
    def getRegisterValue(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    @overload
    def getRegisterValue(self, reg: ghidra.program.model.lang.Register, toAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the current value of the register at the address
        @param reg value of register to get
        @param toAddr value of register at a location
        @return value of register or null
        """
        ...

    @overload
    def getRegisterValue(self, reg: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the value of a register that was set coming from an address to an
         another address.
        @param reg value of register to get
        @param fromAddr location the value came from
        @param toAddr location to get the value of the register coming from fromAddr
        @return value of register or null
        """
        ...

    def getRegisterValueAddressRanges(self, reg: ghidra.program.model.lang.Register) -> ghidra.program.model.address.AddressRangeIterator: ...

    def getRegisterVarnode(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    def getRegisterVarnodeValue(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    def getRegisterVarnodeValue(self, reg: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, signed: bool) -> ghidra.program.model.pcode.Varnode:
        """
        get the value of a register as a varnode (value, space, size)
        @param reg register to get value for
        @param fromAddr from address
        @param toAddr to address
        @param signed true if signed
        @return the register value or null
        """
        ...

    def getRegisters(self) -> List[ghidra.program.model.lang.Register]: ...

    def getReturnVarnode(self, targetFunc: ghidra.program.model.listing.Function) -> List[ghidra.program.model.pcode.Varnode]:
        """
        @param targetFunc function to get a returning varnode for
 
         NOTE: this only gets one, unless there is custom storage on the called function
            there may be bonded ones in the default convention!
        @return varnode that represents where functions place their return value
        """
        ...

    def getStackRegister(self) -> ghidra.program.model.lang.Register:
        """
        @return Register that represents the stack register
        """
        ...

    def getStackVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        @return Varnode that represents the stack register
        """
        ...

    @overload
    def getValue(self, register: ghidra.program.model.lang.Register, signed: bool) -> long: ...

    @overload
    def getValue(self, varnode: ghidra.program.model.pcode.Varnode, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    def getValue(self, varnode: ghidra.program.model.pcode.Varnode, signed: bool, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    def getVarnode(self, spaceID: int, offset: long, size: int) -> ghidra.program.model.pcode.Varnode: ...

    @overload
    def getVarnode(self, space: ghidra.program.model.pcode.Varnode, offset: ghidra.program.model.pcode.Varnode, size: int, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode: ...

    def hasValue(self, register: ghidra.program.model.lang.Register) -> bool: ...

    def hasValueOverRange(self, reg: ghidra.program.model.lang.Register, bval: long, set: ghidra.program.model.address.AddressSet) -> bool: ...

    def hashCode(self) -> int: ...

    def isConstant(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if this is a constant, or a suspect constant
        @param varnode to check
        @return true if should be treated as a constant for most purposes
        """
        ...

    def isExternalSpace(self, spaceID: int) -> bool:
        """
        Check if the space ID is an external space.
 
         External spaces are single locations that have no size
         normally associated with a location in another program.
        @param spaceID the ID of the space
        @return true if is a symbolic space
        """
        ...

    def isRegister(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if the varnode is associated with a register.
        @param varnode to check
        @return true if the varnode is associated with a register
        """
        ...

    def isStackSpaceName(self, spaceName: unicode) -> bool:
        """
        Check if spaceName is associated with the stack
        @param spaceName of address space to check
        @return true if spaceName is associated with the stack space
        """
        ...

    def isStackSymbolicSpace(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if varnode is in the stack space
        @param varnode varnode to check
        @return true if this varnode is stored in the symbolic stack space
        """
        ...

    def isSuspectConstant(self, val1: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if the constant is a suspect constant
         It shouldn't be trusted in certain cases.
         Suspect constants act like constants, but are in a Suspicious
         address space instead of the constant space.
        @param val1 varnode to check
        @return true if varnode is a suspect constant
        """
        ...

    def isSymbol(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if the varnode is associated with a Symbolic location
        @param varnode to check
        @return true if  the varnode is a symbolic location
        """
        ...

    @overload
    def isSymbolicSpace(self, spaceID: int) -> bool:
        """
        Check if the space ID is a symbolic space.
         A symbolic space is a space named after a register/unknown value and
         an offset into that symbolic space.
 
         Symbolic spaces come from the OffsetAddressFactory
        @param spaceID the ID of the space
        @return true if is a symbolic space
        """
        ...

    @overload
    def isSymbolicSpace(self, space: ghidra.program.model.address.AddressSpace) -> bool:
        """
        Check if the space name is a symbolic space.
         A symbolic space is a space named after a register/unknown value and
         an offset into that symbolic space.
 
         Symbolic spaces come from the OffsetAddressFactory
        @param space the address space
        @return true if is a symbolic space
        """
        ...

    def left(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode: ...

    def mergeToFutureFlowState(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def or(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode: ...

    def popMemState(self) -> None:
        """
        restore a previously saved memory state
        """
        ...

    def propogateResults(self, clearContext: bool) -> None:
        """
        Propogate any results that are in the value cache.
        @param clearContext true if the cache should be cleared.
                              The propogation could be for flow purposes, and the
                              processing of the instruction is finished, so it's effects should be kept.
        """
        ...

    def propogateValue(self, reg: ghidra.program.model.lang.Register, node: ghidra.program.model.pcode.Varnode, val: ghidra.program.model.pcode.Varnode, address: ghidra.program.model.address.Address) -> None: ...

    def pushMemState(self) -> None:
        """
        Save the current memory state
        """
        ...

    def putValue(self, out: ghidra.program.model.pcode.Varnode, result: ghidra.program.model.pcode.Varnode, mustClear: bool) -> None: ...

    def readExecutableCode(self) -> bool: ...

    def setCurrentInstruction(self, instr: ghidra.program.model.listing.Instruction) -> None: ...

    def setDebug(self, debugOn: bool) -> None: ...

    def setFutureRegisterValue(self, address: ghidra.program.model.address.Address, regVal: ghidra.program.model.lang.RegisterValue) -> None: ...

    def setReadExecutableCode(self) -> None: ...

    def setRegisterValue(self, value: ghidra.program.model.lang.RegisterValue) -> None: ...

    def setValue(self, register: ghidra.program.model.lang.Register, value: long) -> None: ...

    def subtract(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ghidra.program.util.ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        """
        Subtract two varnodes to get a new value
         This could create a new space and return a varnode pointed into that space
        @param val1 first value
        @param val2 second value
        @return varnode that could be a constant, or an offset into a space
        @throws NotFoundException if any constant is needed not known
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
    def baseContextRegister(self) -> ghidra.program.model.lang.Register: ...

    @property
    def currentInstruction(self) -> None: ...  # No getter available.

    @currentInstruction.setter
    def currentInstruction(self, value: ghidra.program.model.listing.Instruction) -> None: ...

    @property
    def registerValue(self) -> None: ...  # No getter available.

    @registerValue.setter
    def registerValue(self, value: ghidra.program.model.lang.RegisterValue) -> None: ...

    @property
    def registers(self) -> List[object]: ...

    @property
    def stackRegister(self) -> ghidra.program.model.lang.Register: ...

    @property
    def stackVarnode(self) -> ghidra.program.model.pcode.Varnode: ...
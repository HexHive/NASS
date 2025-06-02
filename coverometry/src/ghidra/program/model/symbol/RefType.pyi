import java.lang


class RefType(object):
    """
    RefType defines reference types used to specify the nature of a directional 
     relationship between a source-location and a destination-location where a "location" 
     may correspond to a Address, CodeUnit, CodeBlock or other 
     code related objects.  Reference types are generally identified as either 
     #isData() (see DataRefType) or #isFlow() 
     (see FlowType).
    """

    CALLOTHER_OVERRIDE_CALL: ghidra.program.model.symbol.FlowType = CALLOTHER_OVERRIDE_CALL
    CALLOTHER_OVERRIDE_JUMP: ghidra.program.model.symbol.FlowType = CALLOTHER_OVERRIDE_JUMP
    CALL_OVERRIDE_UNCONDITIONAL: ghidra.program.model.symbol.FlowType = CALL_OVERRIDE_UNCONDITIONAL
    CALL_TERMINATOR: ghidra.program.model.symbol.FlowType = CALL_TERMINATOR
    COMPUTED_CALL: ghidra.program.model.symbol.FlowType = COMPUTED_CALL
    COMPUTED_CALL_TERMINATOR: ghidra.program.model.symbol.FlowType = COMPUTED_CALL_TERMINATOR
    COMPUTED_JUMP: ghidra.program.model.symbol.FlowType = COMPUTED_JUMP
    CONDITIONAL_CALL: ghidra.program.model.symbol.FlowType = CONDITIONAL_CALL
    CONDITIONAL_CALL_TERMINATOR: ghidra.program.model.symbol.FlowType = CONDITIONAL_CALL_TERMINATOR
    CONDITIONAL_COMPUTED_CALL: ghidra.program.model.symbol.FlowType = CONDITIONAL_COMPUTED_CALL
    CONDITIONAL_COMPUTED_JUMP: ghidra.program.model.symbol.FlowType = CONDITIONAL_COMPUTED_JUMP
    CONDITIONAL_JUMP: ghidra.program.model.symbol.FlowType = CONDITIONAL_JUMP
    CONDITIONAL_TERMINATOR: ghidra.program.model.symbol.FlowType = CONDITIONAL_TERMINATOR
    DATA: ghidra.program.model.symbol.RefType = DATA
    DATA_IND: ghidra.program.model.symbol.RefType = DATA_IND
    EXTERNAL_REF: ghidra.program.model.symbol.RefType = EXTERNAL
    FALL_THROUGH: ghidra.program.model.symbol.FlowType = FALL_THROUGH
    FLOW: ghidra.program.model.symbol.FlowType = FLOW
    INDIRECTION: ghidra.program.model.symbol.FlowType = INDIRECTION
    INVALID: ghidra.program.model.symbol.FlowType = INVALID
    JUMP_OVERRIDE_UNCONDITIONAL: ghidra.program.model.symbol.FlowType = JUMP_OVERRIDE_UNCONDITIONAL
    JUMP_TERMINATOR: ghidra.program.model.symbol.FlowType = JUMP_TERMINATOR
    PARAM: ghidra.program.model.symbol.RefType = PARAM
    READ: ghidra.program.model.symbol.RefType = READ
    READ_IND: ghidra.program.model.symbol.RefType = READ_IND
    READ_WRITE: ghidra.program.model.symbol.RefType = READ_WRITE
    READ_WRITE_IND: ghidra.program.model.symbol.RefType = READ_WRITE_IND
    TERMINATOR: ghidra.program.model.symbol.FlowType = TERMINATOR
    THUNK: ghidra.program.model.symbol.RefType = THUNK
    UNCONDITIONAL_CALL: ghidra.program.model.symbol.FlowType = UNCONDITIONAL_CALL
    UNCONDITIONAL_JUMP: ghidra.program.model.symbol.FlowType = UNCONDITIONAL_JUMP
    WRITE: ghidra.program.model.symbol.RefType = WRITE
    WRITE_IND: ghidra.program.model.symbol.RefType = WRITE_IND







    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisplayString(self) -> unicode:
        """
        Returns an easy to read display string for this ref type.
        @return the string
        """
        ...

    def getName(self) -> unicode:
        """
        Returns name of ref-type
        @return the name
        """
        ...

    def getValue(self) -> int:
        """
        Get the int value for this RefType object
        @return the value
        """
        ...

    def hasFallthrough(self) -> bool:
        """
        Returns true if this flow type can fall through
        @return true if can fall through
        """
        ...

    def hashCode(self) -> int: ...

    def isCall(self) -> bool:
        """
        Returns true if the flow is call
        @return true if is a call
        """
        ...

    def isComputed(self) -> bool:
        """
        Returns true if the flow is a computed call or compute jump
        @return true if is computed
        """
        ...

    def isConditional(self) -> bool:
        """
        Returns true if the flow is a conditional call or jump
        @return true if is conditional
        """
        ...

    def isData(self) -> bool:
        """
        Returns true if the reference is to data
        @return true if the reference is to data
        """
        ...

    def isFallthrough(self) -> bool:
        """
        Return true if this flow type is one that does not cause a break in control flow
        @return if this flow type is one that does not cause a break in control flow
        """
        ...

    def isFlow(self) -> bool:
        """
        Returns true if the reference is an instruction flow reference
        @return true if the reference is an instruction flow reference
        """
        ...

    def isIndirect(self) -> bool:
        """
        Returns true if the reference is indirect
        @return true if the reference is indirect
        """
        ...

    def isJump(self) -> bool:
        """
        Returns true if the flow is jump
        @return true if is a jump
        """
        ...

    def isOverride(self) -> bool:
        """
        True if this is an override reference
        @return true if this is an override reference
        """
        ...

    def isRead(self) -> bool:
        """
        Returns true if the reference is a read
        @return true if the reference is a read
        """
        ...

    def isTerminal(self) -> bool:
        """
        Returns true if this instruction terminates
        @return true if terminal
        """
        ...

    def isUnConditional(self) -> bool:
        """
        Returns true if the flow is an unconditional call or jump
        @return true if unconditional
        """
        ...

    def isWrite(self) -> bool:
        """
        Returns true if the reference is a write
        @return true if the reference is a write
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def call(self) -> bool: ...

    @property
    def computed(self) -> bool: ...

    @property
    def conditional(self) -> bool: ...

    @property
    def data(self) -> bool: ...

    @property
    def displayString(self) -> unicode: ...

    @property
    def fallthrough(self) -> bool: ...

    @property
    def flow(self) -> bool: ...

    @property
    def indirect(self) -> bool: ...

    @property
    def jump(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @property
    def override(self) -> bool: ...

    @property
    def read(self) -> bool: ...

    @property
    def terminal(self) -> bool: ...

    @property
    def unConditional(self) -> bool: ...

    @property
    def value(self) -> int: ...

    @property
    def write(self) -> bool: ...
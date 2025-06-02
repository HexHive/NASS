import ghidra.program.model.symbol
import java.lang


class DataRefType(ghidra.program.model.symbol.RefType):
    """
    Class to define reference types for data.
    """









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

    def isData(self) -> bool: ...

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

    def isIndirect(self) -> bool: ...

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

    def isRead(self) -> bool: ...

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

    def isWrite(self) -> bool: ...

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
    def data(self) -> bool: ...

    @property
    def indirect(self) -> bool: ...

    @property
    def read(self) -> bool: ...

    @property
    def write(self) -> bool: ...
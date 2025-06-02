import ghidra.program.model.symbol
import java.lang


class FlowType(ghidra.program.model.symbol.RefType):
    """
    Class to define flow types for instruction (how it
     flows from one instruction to the next)
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

    def hasFallthrough(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isCall(self) -> bool: ...

    def isComputed(self) -> bool: ...

    def isConditional(self) -> bool: ...

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

    def isFlow(self) -> bool: ...

    def isIndirect(self) -> bool:
        """
        Returns true if the reference is indirect
        @return true if the reference is indirect
        """
        ...

    def isJump(self) -> bool: ...

    def isOverride(self) -> bool: ...

    def isRead(self) -> bool:
        """
        Returns true if the reference is a read
        @return true if the reference is a read
        """
        ...

    def isTerminal(self) -> bool: ...

    def isUnConditional(self) -> bool: ...

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
    def flow(self) -> bool: ...

    @property
    def jump(self) -> bool: ...

    @property
    def override(self) -> bool: ...

    @property
    def terminal(self) -> bool: ...

    @property
    def unConditional(self) -> bool: ...
import ghidra.framework.cmd
import ghidra.framework.model
import java.lang


class CreateArrayCmd(object, ghidra.framework.cmd.Command):
    """
    Command to create an array.  All conflicting data will be cleared.
    """





    def __init__(self, addr: ghidra.program.model.address.Address, numElements: int, dt: ghidra.program.model.data.DataType, elementLength: int):
        """
        Constructs a new command for creating arrays.
        @param addr The address at which to create an array.
        @param numElements the number of elements in the array to be created.  
         A 0 element count is permitted but a minimum length will apply for all array instances.
        @param dt the dataType of the elements in the array to be created.
        @param elementLength the size of an element in the array.  Only used for Dynamic
         datatype <code>dt</code> when {@link Dynamic#canSpecifyLength()} returns true.
        """
        ...



    def applyTo(self, obj: ghidra.framework.model.DomainObject) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getName(self) -> unicode: ...

    def getStatusMsg(self) -> unicode: ...

    def hashCode(self) -> int: ...

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
    def name(self) -> unicode: ...

    @property
    def statusMsg(self) -> unicode: ...
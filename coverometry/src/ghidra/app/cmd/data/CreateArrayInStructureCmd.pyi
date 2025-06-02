import ghidra.framework.cmd
import ghidra.framework.model
import java.lang


class CreateArrayInStructureCmd(object, ghidra.framework.cmd.Command):
    """
    Command to create an array inside of a structure. All conflicting components
     within the targeted structure will be replaced with the new array component.
    """





    def __init__(self, addr: ghidra.program.model.address.Address, numElements: int, dt: ghidra.program.model.data.DataType, compPath: List[int]):
        """
        Constructs a new command for creating arrays inside of structures.
         The specified component will be replaced as will subsequent components within 
         the structure required to make room for the new array component.
         NOTE: This is intended for replacing existing components and not for
         simply inserting an array component.
        @param addr The address of the structure that will contain the new array.
        @param numElements the number of elements in the array to be created.  A 0 element count is permitted.
        @param dt the dataType of the elements in the array to be created.
        @param compPath the target component path within the structure of an existing component where 
         the array should be created. The component path is an array of integers where each integer
         is a component index of the component above it.
        """
        ...



    def applyTo(self, obj: ghidra.framework.model.DomainObject) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getName(self) -> unicode:
        """
        @see ghidra.framework.cmd.Command#getName()
        """
        ...

    def getStatusMsg(self) -> unicode:
        """
        @see ghidra.framework.cmd.Command#getStatusMsg()
        """
        ...

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
from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.pcode
import ghidra.program.model.scalar
import java.lang


class HighConstant(ghidra.program.model.pcode.HighVariable):
    """
    A constant that has been given a datatype (like a constant that is really a pointer)
    """





    @overload
    def __init__(self, func: ghidra.program.model.pcode.HighFunction):
        """
        Constructor for use with restoreXml
        @param func is the HighFunction this constant belongs to
        """
        ...

    @overload
    def __init__(self, name: unicode, type: ghidra.program.model.data.DataType, vn: ghidra.program.model.pcode.Varnode, pc: ghidra.program.model.address.Address, func: ghidra.program.model.pcode.HighFunction):
        """
        Construct a constant NOT associated with a symbol
        @param name name of variable
        @param type data type of variable
        @param vn constant varnode
        @param pc code unit address where constant is used
        @param func the associated high function
        """
        ...



    def attachInstances(self, inst: List[ghidra.program.model.pcode.Varnode], rep: ghidra.program.model.pcode.Varnode) -> None:
        """
        Attach an instance or additional location the variable can be found in.
        @param inst varnode where variable can reside.
        @param rep location that variable comes into scope.
        """
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        @return get the data type attached to the variable
        """
        ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction:
        """
        @return the high function associated with this variable.
        """
        ...

    def getInstances(self) -> List[ghidra.program.model.pcode.Varnode]:
        """
        A variable can reside in different locations at various times.
         Get all the instances of the variable.
        @return all the variables instances
        """
        ...

    def getName(self) -> unicode:
        """
        @return get the name of the variable
        """
        ...

    def getOffset(self) -> int:
        """
        Get the offset of this variable into its containing HighSymbol.  If the value
         is -1, this indicates that this HighVariable matches the size and storage of the symbol.
        @return the offset
        """
        ...

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        @return instruction address the variable comes into scope within the function
        """
        ...

    def getRepresentative(self) -> ghidra.program.model.pcode.Varnode:
        """
        @return get the varnode that represents this variable
        """
        ...

    def getScalar(self) -> ghidra.program.model.scalar.Scalar:
        """
        @return constant as a scalar object
        """
        ...

    def getSize(self) -> int:
        """
        @return get the size of the variable
        """
        ...

    def getSymbol(self) -> ghidra.program.model.pcode.HighSymbol: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def requiresDynamicStorage(self) -> bool:
        """
        Return true in when the HighVariable should be recorded (in the database) using dynamic storage
         rather than using the actual address space and offset of the representative varnode.  Dynamic storage
         is typically needed if the actual storage is ephemeral (in the unique space).
        @return true if this needs dynamic storage
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
    def PCAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def scalar(self) -> ghidra.program.model.scalar.Scalar: ...

    @property
    def symbol(self) -> ghidra.program.model.pcode.HighSymbol: ...
from typing import List
import ghidra.program.model.data
import ghidra.program.model.pcode
import java.lang


class HighVariable(object):
    """
    A High-level variable (as in a high-level language like C/C++)
     built out of Varnodes (low-level variables).  This is a base-class
    """









    def attachInstances(self, inst: List[ghidra.program.model.pcode.Varnode], rep: ghidra.program.model.pcode.Varnode) -> None:
        """
        Attach an instance or additional location the variable can be found in.
        @param inst varnode where variable can reside.
        @param rep location that variable comes into scope.
        """
        ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder) -> None:
        """
        Decode this HighVariable from a {@code <high>} element in the stream
        @param decoder is the stream decoder
        @throws DecoderException for invalid encodings
        """
        ...

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

    def getRepresentative(self) -> ghidra.program.model.pcode.Varnode:
        """
        @return get the varnode that represents this variable
        """
        ...

    def getSize(self) -> int:
        """
        @return get the size of the variable
        """
        ...

    def getSymbol(self) -> ghidra.program.model.pcode.HighSymbol:
        """
        Retrieve any underlying HighSymbol
        @return the HighSymbol
        """
        ...

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
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction: ...

    @property
    def instances(self) -> List[ghidra.program.model.pcode.Varnode]: ...

    @property
    def name(self) -> unicode: ...

    @property
    def offset(self) -> int: ...

    @property
    def representative(self) -> ghidra.program.model.pcode.Varnode: ...

    @property
    def size(self) -> int: ...

    @property
    def symbol(self) -> ghidra.program.model.pcode.HighSymbol: ...
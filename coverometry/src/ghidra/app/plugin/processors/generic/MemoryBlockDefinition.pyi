import ghidra.program.model.listing
import java.lang


class MemoryBlockDefinition(object):
    """
    TODO To change the template for this generated type comment go to
     Window - Preferences - Java - Code Style - Code Templates
    """





    def __init__(self, element: ghidra.xml.XmlElement): ...



    def createBlock(self, program: ghidra.program.model.listing.Program) -> None:
        """
        Create memory block within specified program based upon this block specification.
        @param program target program
        @throws LockException if program does not have exclusive access required when adding memory blocks.
        @throws MemoryConflictException if this specification conflicts with an existing memory block in program
        @throws AddressOverflowException if memory space constraints are violated by block specification
        @throws InvalidAddressException if address defined by this block specification is invalid
         for the specified program.  May also indicate an improperly formatted address attribute.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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


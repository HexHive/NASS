from typing import List
import ghidra.program.model.address
import java.lang


class AssemblyBuffer(object):
    """
    A convenience for accumulating bytes output by an Assembler
 
 
     This is most useful when there is not a Program available for assembly. If a program is
     available, consider using Assembler#assemble(Address, String...) and reading the bytes
     from the program. If not, or the program should not be modified, then the pattern of use is
     generally:
 
 
     Address start = space.getAdddress(0x00400000);
     Assembler asm = Assemblers.getAssembler(...);
     AssemblyBuffer buffer = new AssemblyBuffer(asm, start);
 
     buffer.assemble("PUSH R15");
     buffer.assemble("PUSH R14");
     buffer.assemble("PUSH R13");
     ...
     byte[] bytes = buffer.getBytes();
     state.setVar(start, bytes.length, true, bytes);
 
    """





    def __init__(self, asm: ghidra.app.plugin.assembler.Assembler, entry: ghidra.program.model.address.Address):
        """
        Create a buffer with the given assembler starting at the given entry
        @param asm the assembler
        @param entry the starting address where the resulting code will be located
        """
        ...



    @overload
    def assemble(self, line: unicode) -> List[int]:
        """
        Assemble a line and append it to the buffer
        @param line the line
        @return the resulting bytes for the assembled instruction
        @throws AssemblySyntaxException if the instruction cannot be parsed
        @throws AssemblySemanticException if the instruction cannot be encoded
        @throws IOException if the buffer cannot be written
        """
        ...

    @overload
    def assemble(self, at: ghidra.program.model.address.Address, line: unicode) -> List[int]:
        """
        Assemble a line and patch into the buffer
 
         <p>
         This will not grow the buffer, so the instruction being patched must already exist in the
         buffer. The typical use case is to fix up a reference:
 
         <pre>
         AssemblyBuffer buf = new AssemblyBuffer(asm, entry);
         // ...
         Address jumpCheck = buf.getNext();
         buf.assemble("JMP 0x" + buf.getNext()); // Template must accommodate expected jump distance
         // ...
         Address labelCheck = buf.getNext();
         buf.assemble(jumpCheck, "JMP 0x" + labelCheck);
         buf.assemble("CMP ECX, 0");
         // ...
         </pre>
 
         <p>
         This does not check that the patched instruction matches length with the new instruction. In
         fact, the buffer does not remember instruction boundaries at all. If verification is needed,
         the caller should check the lengths of the returned byte arrays for the template and the
         patch.
        @param at the address of the instruction to patch
        @param line the line
        @return the resulting bytes for the assembled instruction
        @throws AssemblySyntaxException if the instruction cannot be parsed
        @throws AssemblySemanticException if the instruction cannot be encoded
        @throws IOException if the buffer cannot be written
        """
        ...

    def emit(self, bytes: List[int]) -> List[int]:
        """
        Append arbitrary bytes to the buffer
        @param bytes the bytes to append
        @return bytes
        @throws IOException if the buffer cannot be written
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBytes(self) -> List[int]:
        """
        Get the complete buffer of bytes
 
         <p>
         However used, the bytes should be placed at the {@code entry} given at construction, unless
         the client is certain the code is position independent.
        @return the bytes
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getNext(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the "cursor" where the next instruction will be assembled
        @return the address
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
    def bytes(self) -> List[int]: ...

    @property
    def next(self) -> ghidra.program.model.address.Address: ...
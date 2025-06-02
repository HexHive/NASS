from typing import List
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.symbol
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import java.lang


class SleighParserContext(object, ghidra.program.model.lang.ParserContext):
    """
    All the recovered context for a single instruction
     The main data structure is the tree of constructors and operands
    """





    @overload
    def __init__(self, origContext: ghidra.app.plugin.processors.sleigh.SleighParserContext, delayByteCount: int):
        """
        Generate context specifically for an instruction that has a delayslot.
         When generating p-code SLEIGH has an alternate interpretation of the "inst_next"
         symbol that takes into account the instruction in the delay slot.  This context is
         generated at the point when specific instruction(s) in the delay slot are known.
        @param origContext is the original context (for the instruction in isolation)
        @param delayByteCount is the number of bytes in instruction stream occupied by the delay slot
        """
        ...

    @overload
    def __init__(self, memBuf: ghidra.program.model.mem.MemBuffer, prototype: ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype, processorContext: ghidra.program.model.lang.ProcessorContextView): ...

    @overload
    def __init__(self, aAddr: ghidra.program.model.address.Address, nAddr: ghidra.program.model.address.Address, rAddr: ghidra.program.model.address.Address, dAddr: ghidra.program.model.address.Address):
        """
        Constructor for building precompiled templates.
         NOTE: This form does not support use of <code>inst_next2</next>.
        @param aAddr = address to which 'inst_start' resolves
        @param nAddr = address to which 'inst_next' resolves
        @param rAddr = special address associated with original call
        @param dAddr = destination address of original call being replaced
        """
        ...



    def addCommit(self, point: ghidra.app.plugin.processors.sleigh.ConstructState, sym: ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol, num: int, mask: int) -> None: ...

    def applyCommits(self, ctx: ghidra.program.model.lang.ProcessorContext) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddr(self) -> ghidra.program.model.address.Address:
        """
        get address of current instruction
        @return address of current instruction
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getConstSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get constant address space
        @return constant address space
        """
        ...

    def getContextBits(self, startbit: int, bitsize: int) -> int:
        """
        Get bits from context into an int
        @param startbit is the index of the first bit to fetch
        @param bitsize number of bits (range: 1 - 32)
        @return the packed bits
        """
        ...

    @overload
    def getContextBytes(self) -> List[int]:
        """
        Get full set of context bytes.  Sleigh only supports context
         which is a multiple of 4-bytes (i.e., size of int)
        @return the array of context data
        """
        ...

    @overload
    def getContextBytes(self, bytestart: int, bytesize: int) -> int:
        """
        Get bytes from context into an int
        @param bytestart is the index of the first byte to fetch
        @param bytesize number of bytes (range: 1 - 4)
        @return the packed bytes from context
        """
        ...

    def getContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the processor context value as a RegisterValue
        @return processor context value
        """
        ...

    def getCurSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get address space containing current instruction
        @return address space containing current instruction
        """
        ...

    def getFixedHandle(self, constructState: ghidra.app.plugin.processors.sleigh.ConstructState) -> ghidra.app.plugin.processors.sleigh.FixedHandle: ...

    def getFlowDestAddr(self) -> ghidra.program.model.address.Address: ...

    def getFlowRefAddr(self) -> ghidra.program.model.address.Address: ...

    def getInstructionBits(self, offset: int, startbit: int, size: int) -> int:
        """
        Get bits from the instruction stream into an int
         (packed in big endian format).  Uninitialized or 
         undefined memory will return zero bit values.
        @param offset offset relative start of this context
        @param startbit is the index of the first bit to fetch
        @param size is the number of bits to fetch
        @return requested bit-range value
        @throws MemoryAccessException if no bytes are available at first byte when (offset+bytestart/8==0).
        """
        ...

    def getInstructionBytes(self, offset: int, bytestart: int, size: int) -> int:
        """
        Get bytes from the instruction stream into an int
         (packed in big endian format).  Uninitialized or 
         undefined memory will return zero byte values.
        @param offset offset relative start of this context
        @param bytestart pattern byte offset relative to specified context offset
        @param size is the number of bytes to fetch
        @return requested byte-range value
        @throws MemoryAccessException if no bytes are available at first byte when (offset+bytestart==0).
        """
        ...

    def getMemBuffer(self) -> ghidra.program.model.mem.MemBuffer:
        """
        Get memory buffer for current instruction which may also be used to parse next instruction
         or delay slot instructions.
        @return memory buffer for current instruction
        """
        ...

    def getN2addr(self) -> ghidra.program.model.address.Address:
        """
        Get address of instruction after the next instruction.  This may return {@link #getNaddr()}
         if this context instance does not support use of {@code inst_next2} or parse of next 
         instruction fails.
        @return address of instruction after the next instruction or null
        """
        ...

    def getNaddr(self) -> ghidra.program.model.address.Address:
        """
        Get address of instruction after current instruction.  This may return null if this context 
         instance does not support use of {@code inst_next} or next address falls beyond end of
         address space.
        @return address of next instruction or null
        """
        ...

    def getPrototype(self) -> ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype: ...

    def hashCode(self) -> int: ...

    def isValid(self, buf: ghidra.program.model.mem.MemBuffer) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setContextWord(self, i: int, val: int, mask: int) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addr(self) -> ghidra.program.model.address.Address: ...

    @property
    def constSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def contextBytes(self) -> List[int]: ...

    @property
    def contextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue: ...

    @property
    def curSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def flowDestAddr(self) -> ghidra.program.model.address.Address: ...

    @property
    def flowRefAddr(self) -> ghidra.program.model.address.Address: ...

    @property
    def memBuffer(self) -> ghidra.program.model.mem.MemBuffer: ...

    @property
    def n2addr(self) -> ghidra.program.model.address.Address: ...

    @property
    def naddr(self) -> ghidra.program.model.address.Address: ...

    @property
    def prototype(self) -> ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype: ...
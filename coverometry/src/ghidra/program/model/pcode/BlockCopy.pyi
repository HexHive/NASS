import ghidra.program.model.address
import ghidra.program.model.pcode
import java.lang


class BlockCopy(ghidra.program.model.pcode.PcodeBlock):
    """
    Placeholder for a basic block (BlockBasic) within a structured
     control-flow graph. It originally mirrors the in and out edges of
     the basic block, but edges may be modified during the structuring process.
     This copy holds a reference to the actual basic block
    """





    @overload
    def __init__(self): ...

    @overload
    def __init__(self, r: object, addr: ghidra.program.model.address.Address): ...



    def calcDepth(self, leaf: ghidra.program.model.pcode.PcodeBlock) -> int: ...

    def decode(self, decoder: ghidra.program.model.pcode.Decoder, resolver: ghidra.program.model.pcode.BlockMap) -> None:
        """
        Decode this block from a stream
        @param decoder is the stream decoder
        @param resolver is the map from reference to block object
        @throws DecoderException for errors in the encoding
        """
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode this block to a stream
        @param encoder is the stream encoder
        @throws IOException for errors writing to the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAltIndex(self) -> int:
        """
        @return the alternative index, used as an id for the original basic block Object
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFalseOut(self) -> ghidra.program.model.pcode.PcodeBlock:
        """
        Assuming paths out of this block depend on a boolean condition
        @return the PcodeBlock coming out of this if the condition is false
        """
        ...

    def getFrontLeaf(self) -> ghidra.program.model.pcode.PcodeBlock: ...

    def getIn(self, i: int) -> ghidra.program.model.pcode.PcodeBlock: ...

    def getInRevIndex(self, i: int) -> int:
        """
        Get reverse index of the i-th incoming block. I.e. this.getIn(i).getOut(reverse_index) == this
        @param i is the incoming block to request reverse index from
        @return the reverse index
        """
        ...

    def getInSize(self) -> int: ...

    def getIndex(self) -> int: ...

    def getOut(self, i: int) -> ghidra.program.model.pcode.PcodeBlock: ...

    def getOutRevIndex(self, i: int) -> int:
        """
        Get reverse index of the i-th outgoing block. I.e this.getOut(i).getIn(reverse_index) == this
        @param i is the outgoing block to request reverse index from
        @return the reverse index
        """
        ...

    def getOutSize(self) -> int: ...

    def getParent(self) -> ghidra.program.model.pcode.PcodeBlock: ...

    def getRef(self) -> object:
        """
        @return the underlying basic block Object
        """
        ...

    def getStart(self) -> ghidra.program.model.address.Address: ...

    def getStop(self) -> ghidra.program.model.address.Address: ...

    def getTrueOut(self) -> ghidra.program.model.pcode.PcodeBlock:
        """
        Assuming paths out of this block depend on a boolean condition
        @return the PcodeBlock coming out of this if the condition is true
        """
        ...

    def getType(self) -> int: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def nameToType(name: unicode) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setIndex(self, i: int) -> None: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def typeToName(type: int) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def altIndex(self) -> int: ...

    @property
    def ref(self) -> object: ...

    @property
    def start(self) -> ghidra.program.model.address.Address: ...

    @property
    def stop(self) -> ghidra.program.model.address.Address: ...
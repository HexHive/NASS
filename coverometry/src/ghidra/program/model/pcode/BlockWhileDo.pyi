import ghidra.program.model.address
import ghidra.program.model.pcode
import java.lang


class BlockWhileDo(ghidra.program.model.pcode.BlockGraph):
    """
    Block representing a while-do (exit from the top) loop construction
 
     possible multiple incoming edges
     1 outgoing exit edge
     1 (implied) loop edge
 
     1 interior block representing the top of the loop and the decision point for staying in the loop
     1 interior block representing the body of the loop, which always exits back to the top of the loop
    """





    def __init__(self): ...



    def addBlock(self, bl: ghidra.program.model.pcode.PcodeBlock) -> None:
        """
        Add a block to this container. There are (initially) no edges between
         it and any other block in the container.
        @param bl is the new block to add
        """
        ...

    def addEdge(self, begin: ghidra.program.model.pcode.PcodeBlock, end: ghidra.program.model.pcode.PcodeBlock) -> None:
        """
        Add a directed edge between two blocks in this container
        @param begin is the "from" block of the edge
        @param end is the "to" block of the edge
        """
        ...

    def calcDepth(self, leaf: ghidra.program.model.pcode.PcodeBlock) -> int: ...

    @overload
    def decode(self, decoder: ghidra.program.model.pcode.Decoder) -> None:
        """
        Decode all blocks and edges in this container from a stream.
        @param decoder is the stream decoder
        @throws DecoderException if there are invalid encodings
        """
        ...

    @overload
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

    def getBlock(self, i: int) -> ghidra.program.model.pcode.PcodeBlock:
        """
        Retrieve the i-th block from this container
        @param i is the index of the block to fetch
        @return the block
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

    def getSize(self) -> int:
        """
        @return the number of blocks in this container
        """
        ...

    def getStart(self) -> ghidra.program.model.address.Address:
        """
        @return the first Address covered by this block
        """
        ...

    def getStop(self) -> ghidra.program.model.address.Address:
        """
        @return the last Address covered by this block
        """
        ...

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

    def setIndices(self) -> None:
        """
        Assign a unique index to all blocks in this container. After this call,
         getBlock(i) will return the block that satisfies block.getIndex() == i
        """
        ...

    def toString(self) -> unicode: ...

    def transferObjectRef(self, ingraph: ghidra.program.model.pcode.BlockGraph) -> None:
        """
        Recursively run through this structured BlockGraph finding the BlockCopy leaves.
         Using the BlockCopy altindex, lookup the original BlockCopy in -ingraph- and
         transfer the Object ref and Address into the leaf
        @param ingraph is the original flow graph
        """
        ...

    @staticmethod
    def typeToName(type: int) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


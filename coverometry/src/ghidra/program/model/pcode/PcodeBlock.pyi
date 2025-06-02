import ghidra.program.model.address
import ghidra.program.model.pcode
import java.lang
import java.util


class PcodeBlock(object):
    """
    Blocks of PcodeOps
    """

    BASIC: int = 1
    CONDITION: int = 7
    COPY: int = 3
    DOWHILE: int = 12
    GOTO: int = 4
    GRAPH: int = 2
    IFELSE: int = 9
    IFGOTO: int = 10
    INFLOOP: int = 14
    LIST: int = 6
    MULTIGOTO: int = 5
    PLAIN: int = 0
    PROPERIF: int = 8
    SWITCH: int = 13
    WHILEDO: int = 11




    class BlockEdge(object):
        label: int
        point: ghidra.program.model.pcode.PcodeBlock
        reverse_index: int



        @overload
        def __init__(self): ...

        @overload
        def __init__(self, __a0: ghidra.program.model.pcode.PcodeBlock, __a1: int, __a2: int): ...



        @overload
        def decode(self, __a0: ghidra.program.model.pcode.Decoder, __a1: ghidra.program.model.pcode.BlockMap) -> None: ...

        @overload
        def decode(self, __a0: ghidra.program.model.pcode.Decoder, __a1: java.util.ArrayList) -> None: ...

        def encode(self, __a0: ghidra.program.model.pcode.Encoder) -> None: ...

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



    def __init__(self): ...



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
    def falseOut(self) -> ghidra.program.model.pcode.PcodeBlock: ...

    @property
    def frontLeaf(self) -> ghidra.program.model.pcode.PcodeBlock: ...

    @property
    def inSize(self) -> int: ...

    @property
    def index(self) -> int: ...

    @index.setter
    def index(self, value: int) -> None: ...

    @property
    def outSize(self) -> int: ...

    @property
    def parent(self) -> ghidra.program.model.pcode.PcodeBlock: ...

    @property
    def start(self) -> ghidra.program.model.address.Address: ...

    @property
    def stop(self) -> ghidra.program.model.address.Address: ...

    @property
    def trueOut(self) -> ghidra.program.model.pcode.PcodeBlock: ...

    @property
    def type(self) -> int: ...
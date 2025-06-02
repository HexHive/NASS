import ghidra.program.model.data
import ghidra.program.model.pcode
import java.lang


class ParamMeasure(object):
    """
    ParamMeasure
    """





    def __init__(self):
        """
        Constructs a ParamMeasure Object.
         <b>The ParamMeasure will be empty until {@link #decode} is invoked.</b>
        """
        ...



    def decode(self, decoder: ghidra.program.model.pcode.Decoder, factory: ghidra.program.model.pcode.PcodeFactory) -> None:
        """
        Decode a ParamMeasure object from the stream.
        @param decoder is the stream decoder
        @param factory pcode factory
        @throws DecoderException for an invalid encoding
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getRank(self) -> int: ...

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

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
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def empty(self) -> bool: ...

    @property
    def rank(self) -> int: ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode: ...
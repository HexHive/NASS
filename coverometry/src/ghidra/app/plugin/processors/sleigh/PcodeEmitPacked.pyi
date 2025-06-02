import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.template
import ghidra.program.model.address
import java.lang


class PcodeEmitPacked(ghidra.app.plugin.processors.sleigh.PcodeEmit):





    class LabelRef(object):
        labelIndex: int
        labelSize: int
        opIndex: int
        streampos: int



        def __init__(self, __a0: ghidra.app.plugin.processors.sleigh.PcodeEmitPacked, __a1: int, __a2: int, __a3: int, __a4: int): ...



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



    def __init__(self, encoder: ghidra.program.model.pcode.PatchEncoder, walk: ghidra.app.plugin.processors.sleigh.ParserWalker, ictx: ghidra.program.model.lang.InstructionContext, fallOffset: int, override: ghidra.program.model.pcode.PcodeOverride):
        """
        Pcode emitter constructor for producing a packed binary representation.
        @param encoder is the stream encoder to emit to
        @param walk parser walker
        @param ictx instruction contexts
        @param fallOffset default instruction fall offset (i.e., instruction length including delay slotted instructions)
        @param override required if pcode overrides are to be utilized
        """
        ...



    def build(self, construct: ghidra.app.plugin.processors.sleigh.template.ConstructTpl, secnum: int) -> None: ...

    def emitHeader(self) -> None: ...

    def emitTail(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFallOffset(self) -> int: ...

    def getStartAddress(self) -> ghidra.program.model.address.Address: ...

    def getWalker(self) -> ghidra.app.plugin.processors.sleigh.ParserWalker: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def resolveRelatives(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


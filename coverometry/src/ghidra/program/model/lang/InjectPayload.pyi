from typing import List
import ghidra.app.plugin.processors.sleigh
import ghidra.program.model.lang
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class InjectPayload(object):
    """
    InjectPayload encapsulates a semantic (p-code) override which can be injected
     into analyses that work with p-code (Decompiler, SymbolicPropagator)
     The payload typically replaces either a subroutine call or a userop
    """

    CALLFIXUP_TYPE: int = 1
    CALLMECHANISM_TYPE: int = 3
    CALLOTHERFIXUP_TYPE: int = 2
    EXECUTABLEPCODE_TYPE: int = 4




    class InjectParameter(object):




        def __init__(self, __a0: unicode, __a1: int): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getIndex(self) -> int: ...

        def getName(self) -> unicode: ...

        def getSize(self) -> int: ...

        def hashCode(self) -> int: ...

        def isEquivalent(self, __a0: ghidra.program.model.lang.InjectPayload.InjectParameter) -> bool: ...

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
        def index(self) -> int: ...

        @property
        def name(self) -> unicode: ...

        @property
        def size(self) -> int: ...





    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode configuration parameters as a \<pcode> element to stream
        @param encoder is the stream encoder
        @throws IOException for errors writing to the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getInput(self) -> List[ghidra.program.model.lang.InjectPayload.InjectParameter]:
        """
        @return array of any input parameters for this inject
        """
        ...

    def getName(self) -> unicode:
        """
        @return formal name for this injection
        """
        ...

    def getOutput(self) -> List[ghidra.program.model.lang.InjectPayload.InjectParameter]:
        """
        @return array of any output parameters for this inject
        """
        ...

    def getParamShift(self) -> int:
        """
        @return number of parameters from the original call which should be truncated
        """
        ...

    def getPcode(self, program: ghidra.program.model.listing.Program, con: ghidra.program.model.lang.InjectContext) -> List[ghidra.program.model.pcode.PcodeOp]:
        """
        A convenience function wrapping the inject method, to produce the final set
         of PcodeOp objects in an array
        @param program is the Program for which injection is happening
        @param con is the context for injection
        @return the array of PcodeOps
        @throws MemoryAccessException for problems establishing the injection context
        @throws IOException for problems while emitting the injection p-code
        @throws UnknownInstructionException if there is no underlying instruction being injected
        @throws NotFoundException if an expected aspect of the injection is not present in context
        """
        ...

    def getSource(self) -> unicode:
        """
        @return a String describing the source of this payload
        """
        ...

    def getType(self) -> int:
        """
        @return the type of this injection:  CALLFIXUP_TYPE, CALLMECHANISM_TYPE, etc.
        """
        ...

    def hashCode(self) -> int: ...

    def inject(self, context: ghidra.program.model.lang.InjectContext, emit: ghidra.app.plugin.processors.sleigh.PcodeEmit) -> None:
        """
        Given a context, send the p-code payload to the emitter
        @param context is the context for injection
        @param emit is the object accumulating the final p-code
        @throws MemoryAccessException for problems establishing the injection context
        @throws IOException for problems while emitting the injection p-code
        @throws UnknownInstructionException if there is no underlying instruction being injected
        @throws NotFoundException if an expected aspect of the injection is not present in context
        """
        ...

    def isEquivalent(self, obj: ghidra.program.model.lang.InjectPayload) -> bool:
        """
        Determine if this InjectPayload and another instance are equivalent
         (have the same name and generate the same p-code)
        @param obj is the other payload
        @return true if they are equivalent
        """
        ...

    def isErrorPlaceholder(self) -> bool:
        """
        If parsing a payload (from XML) fails, a placeholder payload may be substituted and
         this method returns true for the substitute.  In all other cases, this returns false.
        @return true if this is a placeholder for a payload with parse errors.
        """
        ...

    def isFallThru(self) -> bool:
        """
        @return true if the injected p-code falls thru
        """
        ...

    def isIncidentalCopy(self) -> bool:
        """
        @return true if this inject's COPY operations should be treated as incidental
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, language: ghidra.app.plugin.processors.sleigh.SleighLanguage) -> None:
        """
        Restore the payload from an XML stream.  The root expected document is
         the \<pcode> tag, which may be wrapped with another tag by the derived class.
        @param parser is the XML stream
        @param language is used to resolve registers and address spaces
        @throws XmlParseException for badly formed XML
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
    def errorPlaceholder(self) -> bool: ...

    @property
    def fallThru(self) -> bool: ...

    @property
    def incidentalCopy(self) -> bool: ...

    @property
    def input(self) -> List[ghidra.program.model.lang.InjectPayload.InjectParameter]: ...

    @property
    def name(self) -> unicode: ...

    @property
    def output(self) -> List[ghidra.program.model.lang.InjectPayload.InjectParameter]: ...

    @property
    def paramShift(self) -> int: ...

    @property
    def source(self) -> unicode: ...

    @property
    def type(self) -> int: ...
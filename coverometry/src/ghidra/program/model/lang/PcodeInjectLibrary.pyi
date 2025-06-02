from typing import List
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class PcodeInjectLibrary(object):




    @overload
    def __init__(self, l: ghidra.app.plugin.processors.sleigh.SleighLanguage): ...

    @overload
    def __init__(self, op2: ghidra.program.model.lang.PcodeInjectLibrary):
        """
        Clone a library so that a Program can extend the library without
         modifying the base library from Language.  InjectPayloads can be considered
         immutable and don't need to be cloned.
        @param op2 is the library to clone
        """
        ...



    def allocateInject(self, sourceName: unicode, name: unicode, tp: int) -> ghidra.program.model.lang.InjectPayload:
        """
        The main InjectPayload factory interface. This can be overloaded by derived libraries
         to produce custom dynamic payloads.
        @param sourceName is a description of the source of the payload
        @param name is the formal name of the payload
        @param tp is the type of payload:  CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.
        @return the newly minted InjectPayload
        """
        ...

    def buildInjectContext(self) -> ghidra.program.model.lang.InjectContext: ...

    def clone(self) -> ghidra.program.model.lang.PcodeInjectLibrary:
        """
        @return A clone of this library
        """
        ...

    def encodeCompilerSpec(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode the parts of the inject library that come from the compiler spec
         to the output stream
        @param encoder is the stream encoder
        @throws IOException for errors writing to the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getCallFixupNames(self) -> List[unicode]:
        """
        @return a list of names for all installed call-fixups
        """
        ...

    def getCallotherFixupNames(self) -> List[unicode]:
        """
        @return a list of names for all installed callother-fixups
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getConstantPool(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.lang.ConstantPool:
        """
        Get the constant pool associated with the given Program
        @param program is the given Program
        @return the ConstantPool associated with the Program
        @throws IOException for issues constructing the object
        """
        ...

    def getPayload(self, type: int, name: unicode) -> ghidra.program.model.lang.InjectPayload: ...

    def getProgramPayloads(self) -> List[ghidra.program.model.lang.InjectPayloadSleigh]:
        """
        @return an array of all the program specific payloads (or null)
        """
        ...

    def hasProgramPayload(self, nm: unicode, type: int) -> bool:
        """
        Determine if the given payload name and type exists and is an extension
         of the program.
        @param nm is the payload name
        @param type is the payload type
        @return true if the program extension exists
        """
        ...

    def hasUserDefinedOp(self, name: unicode) -> bool:
        """
        Determine if the language has a given user-defined op.
         In which case, a CALLOTHER_FIXUP can be installed for it.
        @param name is the putative name of the user-defined op
        @return true if the user-defined op exists
        """
        ...

    def hashCode(self) -> int: ...

    def isEquivalent(self, obj: ghidra.program.model.lang.PcodeInjectLibrary) -> bool:
        """
        Compare that this and the other library contain all equivalent payloads
        @param obj is the other library
        @return true if all payloads are equivalent
        """
        ...

    def isOverride(self, nm: unicode, type: int) -> bool:
        """
        Check if a specific payload has been overridden by a user extension
        @param nm is the name of the payload
        @param type is the type of payload
        @return true if the payload is overridden
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parseInject(self, payload: ghidra.program.model.lang.InjectPayload) -> None:
        """
        Convert the XML string representation of the given payload to a ConstructTpl
         The payload should be unattached (not already installed in the library)
        @param payload is the given payload whose XML should be converted
        @throws SleighException if there is any parsing issue
        """
        ...

    def restoreXmlInject(self, source: unicode, name: unicode, tp: int, parser: ghidra.xml.XmlPullParser) -> ghidra.program.model.lang.InjectPayload: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def callFixupNames(self) -> List[unicode]: ...

    @property
    def callotherFixupNames(self) -> List[unicode]: ...

    @property
    def programPayloads(self) -> List[ghidra.program.model.lang.InjectPayloadSleigh]: ...
from typing import List
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.template
import ghidra.app.util.pcodeInject
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class InjectGetField(ghidra.app.util.pcodeInject.InjectPayloadJava):




    def __init__(self, __a0: unicode, __a1: ghidra.app.plugin.processors.sleigh.SleighLanguage, __a2: long): ...



    def encode(self, __a0: ghidra.program.model.pcode.Encoder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getDummyPcode(__a0: ghidra.program.model.address.AddressFactory) -> ghidra.app.plugin.processors.sleigh.template.ConstructTpl: ...

    def getInput(self) -> List[ghidra.program.model.lang.InjectPayload.InjectParameter]: ...

    def getName(self) -> unicode: ...

    def getOutput(self) -> List[ghidra.program.model.lang.InjectPayload.InjectParameter]: ...

    def getParamShift(self) -> int: ...

    def getPcode(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.program.model.lang.InjectContext) -> List[ghidra.program.model.pcode.PcodeOp]: ...

    def getSource(self) -> unicode: ...

    def getType(self) -> int: ...

    def hashCode(self) -> int: ...

    def inject(self, __a0: ghidra.program.model.lang.InjectContext, __a1: ghidra.app.plugin.processors.sleigh.PcodeEmit) -> None: ...

    def isEquivalent(self, __a0: ghidra.program.model.lang.InjectPayload) -> bool: ...

    def isErrorPlaceholder(self) -> bool: ...

    def isFallThru(self) -> bool: ...

    def isIncidentalCopy(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def restoreXml(self, __a0: ghidra.xml.XmlPullParser, __a1: ghidra.app.plugin.processors.sleigh.SleighLanguage) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


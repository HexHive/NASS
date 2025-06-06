import ghidra.program.model.address
import ghidra.program.model.pcode
import java.io
import java.lang


class XmlEncode(object, ghidra.program.model.pcode.Encoder):
    """
    An XML based encoder
     The underlying transfer encoding is an XML document.
     The encoder is initialized with a StringBuilder which will receive the XML document as calls
     are made on the encoder.
    """





    def __init__(self): ...



    def clear(self) -> None: ...

    def closeElement(self, elemId: ghidra.program.model.pcode.ElementId) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openElement(self, elemId: ghidra.program.model.pcode.ElementId) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeBool(self, attribId: ghidra.program.model.pcode.AttributeId, val: bool) -> None: ...

    def writeSignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId, val: long) -> None: ...

    def writeSpace(self, attribId: ghidra.program.model.pcode.AttributeId, spc: ghidra.program.model.address.AddressSpace) -> None: ...

    def writeString(self, attribId: ghidra.program.model.pcode.AttributeId, val: unicode) -> None: ...

    def writeStringIndexed(self, attribId: ghidra.program.model.pcode.AttributeId, index: int, val: unicode) -> None: ...

    def writeTo(self, stream: java.io.OutputStream) -> None: ...

    def writeUnsignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId, val: long) -> None: ...

    @property
    def empty(self) -> bool: ...
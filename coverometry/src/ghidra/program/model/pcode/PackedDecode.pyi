import ghidra.program.model.address
import ghidra.program.model.pcode
import java.io
import java.lang


class PackedDecode(object, ghidra.program.model.pcode.Decoder):
    ATTRIBUTE: int = 192
    ELEMENTID_MASK: int = 31
    ELEMENT_END: int = 128
    ELEMENT_START: int = 64
    HEADEREXTEND_MASK: int = 32
    HEADER_MASK: int = 192
    LENGTHCODE_MASK: int = 15
    RAWDATA_BITSPERBYTE: int = 7
    RAWDATA_MARKER: int = 128
    RAWDATA_MASK: int = 127
    SPECIALSPACE_FSPEC: int = 2
    SPECIALSPACE_IOP: int = 3
    SPECIALSPACE_JOIN: int = 1
    SPECIALSPACE_SPACEBASE: int = 4
    SPECIALSPACE_STACK: int = 0
    TYPECODE_ADDRESSSPACE: int = 5
    TYPECODE_BOOLEAN: int = 1
    TYPECODE_SHIFT: int = 4
    TYPECODE_SIGNEDINT_NEGATIVE: int = 3
    TYPECODE_SIGNEDINT_POSITIVE: int = 2
    TYPECODE_SPECIALSPACE: int = 6
    TYPECODE_STRING: int = 7
    TYPECODE_UNSIGNEDINT: int = 4



    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory): ...



    def clear(self) -> None: ...

    def closeElement(self, id: int) -> None: ...

    def closeElementSkipping(self, id: int) -> None: ...

    def endIngest(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    def getClass(self) -> java.lang.Class: ...

    def getIndexedAttributeId(self, attribId: ghidra.program.model.pcode.AttributeId) -> int: ...

    def getNextAttributeId(self) -> int: ...

    def hashCode(self) -> int: ...

    def ingestStream(self, stream: java.io.InputStream) -> None: ...

    def isEmpty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def open(self, max: int, source: unicode) -> None: ...

    @overload
    def openElement(self) -> int: ...

    @overload
    def openElement(self, elemId: ghidra.program.model.pcode.ElementId) -> int: ...

    def peekElement(self) -> int: ...

    @overload
    def readBool(self) -> bool: ...

    @overload
    def readBool(self, attribId: ghidra.program.model.pcode.AttributeId) -> bool: ...

    @overload
    def readSignedInteger(self) -> long: ...

    @overload
    def readSignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId) -> long: ...

    @overload
    def readSignedIntegerExpectString(self, expect: unicode, expectval: long) -> long: ...

    @overload
    def readSignedIntegerExpectString(self, attribId: ghidra.program.model.pcode.AttributeId, expect: unicode, expectval: long) -> long: ...

    @overload
    def readSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @overload
    def readSpace(self, attribId: ghidra.program.model.pcode.AttributeId) -> ghidra.program.model.address.AddressSpace: ...

    @overload
    def readString(self) -> unicode: ...

    @overload
    def readString(self, attribId: ghidra.program.model.pcode.AttributeId) -> unicode: ...

    @overload
    def readUnsignedInteger(self) -> long: ...

    @overload
    def readUnsignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId) -> long: ...

    def rewindAttributes(self) -> None: ...

    def skipElement(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    @property
    def empty(self) -> bool: ...

    @property
    def nextAttributeId(self) -> int: ...
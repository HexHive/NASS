import ghidra.program.model.address
import ghidra.program.model.pcode
import java.io
import java.lang


class PatchEncoder(ghidra.program.model.pcode.Encoder, object):
    """
    This is an encoder that produces encodings that can be retroactively patched.
     The contained encoding is expected to be byte based.  The user can record a position
     in the encoding by calling the size() method in the middle of encoding, and then later
     use the returned offset to call the patchIntegerAttribute() method and modify the
     encoding at the recorded position.
    """









    def clear(self) -> None: ...

    def closeElement(self, __a0: ghidra.program.model.pcode.ElementId) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openElement(self, __a0: ghidra.program.model.pcode.ElementId) -> None: ...

    def patchIntegerAttribute(self, pos: int, attribId: ghidra.program.model.pcode.AttributeId, val: long) -> bool:
        """
        Replace an integer attribute for the element at the given position.
         The position is assumed to be at an open directive for the element containing the
         attribute to be patched.
        @param pos is the given position
        @param attribId is the attribute to be patched
        @param val is the new value to insert
        @return true if the attribute is successfully patched
        """
        ...

    def size(self) -> int:
        """
        The returned value can be used as a position for later modification
        @return the number of bytes written to this stream so far
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeBool(self, __a0: ghidra.program.model.pcode.AttributeId, __a1: bool) -> None: ...

    def writeSignedInteger(self, __a0: ghidra.program.model.pcode.AttributeId, __a1: long) -> None: ...

    def writeSpace(self, __a0: ghidra.program.model.pcode.AttributeId, __a1: ghidra.program.model.address.AddressSpace) -> None: ...

    def writeSpaceId(self, attribId: ghidra.program.model.pcode.AttributeId, spaceId: long) -> None:
        """
        Write a given raw spaceid (as returned by AddressSpace.getSpaceID()) as an attribute.
         The effect is the same as if writeSpace() was called with the AddressSpace matching
         the spaceid, i.e. the decoder will read this as just space attribute.
        @param attribId is the attribute
        @param spaceId is the given spaceid
        """
        ...

    def writeString(self, __a0: ghidra.program.model.pcode.AttributeId, __a1: unicode) -> None: ...

    def writeStringIndexed(self, __a0: ghidra.program.model.pcode.AttributeId, __a1: int, __a2: unicode) -> None: ...

    def writeTo(self, __a0: java.io.OutputStream) -> None: ...

    def writeUnsignedInteger(self, __a0: ghidra.program.model.pcode.AttributeId, __a1: long) -> None: ...

    @property
    def empty(self) -> bool: ...
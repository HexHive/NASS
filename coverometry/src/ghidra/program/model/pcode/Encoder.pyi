import ghidra.program.model.address
import ghidra.program.model.pcode
import java.io
import java.lang


class Encoder(object):
    """
    An interface for writing structured data to a stream

     The resulting encoded data is structured similarly to an XML document. The document contains a nested set
     of \elements, with labels corresponding to the ElementId class. A single element can hold
     zero or more attributes and zero or more child elements.  An attribute holds a primitive
     data element (boolean, long, String) and is labeled by an AttributeId. The document is written
     using a sequence of openElement() and closeElement() calls, intermixed with write*() calls to encode
     the data primitives.  All primitives written using a write*() call are associated with current open element,
     and all write*() calls for one element must come before opening any child element.
     The traditional XML element text content can be written using the special ATTRIB_CONTENT AttributeId, which
     must be the last write*() call associated with the specific element.
    """









    def clear(self) -> None:
        """
        Clear any state associated with the encoder
         The encoder should be ready to write a new document after this call.
        """
        ...

    def closeElement(self, elemId: ghidra.program.model.pcode.ElementId) -> None:
        """
        End the current element in the encoding
         The current element must match the given annotation or an exception is thrown.
        @param elemId is the given (expected) annotation for the current element
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool:
        """
        The encoder is considered empty if the writeTo() method would output zero bytes
        @return true if there are no bytes in the encoder
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openElement(self, elemId: ghidra.program.model.pcode.ElementId) -> None:
        """
        Begin a new element in the encoding
         The element will have the given ElementId annotation and becomes the \e current element.
        @param elemId is the given ElementId annotation
        @throws IOException for errors in the underlying stream
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeBool(self, attribId: ghidra.program.model.pcode.AttributeId, val: bool) -> None:
        """
        Write an annotated boolean value into the encoding
         The boolean data is associated with the given AttributeId annotation and the current open element.
        @param attribId is the given AttributeId annotation
        @param val is boolean value to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    def writeSignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId, val: long) -> None:
        """
        Write an annotated signed integer value into the encoding
         The integer is associated with the given AttributeId annotation and the current open element.
        @param attribId is the given AttributeId annotation
        @param val is the signed integer value to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    def writeSpace(self, attribId: ghidra.program.model.pcode.AttributeId, spc: ghidra.program.model.address.AddressSpace) -> None:
        """
        Write an address space reference into the encoding
         The address space is associated with the given AttributeId annotation and the current open element.
        @param attribId is the given AttributeId annotation
        @param spc is the address space to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    def writeString(self, attribId: ghidra.program.model.pcode.AttributeId, val: unicode) -> None:
        """
        Write an annotated string into the encoding
         The string is associated with the given AttributeId annotation and the current open element.
        @param attribId is the given AttributeId annotation
        @param val is the string to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    def writeStringIndexed(self, attribId: ghidra.program.model.pcode.AttributeId, index: int, val: unicode) -> None:
        """
        Write an annotated string, using an indexed attribute, into the encoding.
         Multiple attributes with a shared name can be written to the same element by calling this
         method multiple times with a different index value. The encoding will use attribute ids up
         to the base id plus the maximum index passed in.  Implementors must be careful to not use
         other attributes with ids bigger than the base id within the element taking the indexed attribute.
        @param attribId is the shared AttributeId
        @param index is the unique index to associated with the string
        @param val is the string to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    def writeTo(self, stream: java.io.OutputStream) -> None:
        """
        Dump all the accumulated bytes in this encoder to the stream.
        @param stream is the output stream
        @throws IOException for errors during the write operation
        """
        ...

    def writeUnsignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId, val: long) -> None:
        """
        Write an annotated unsigned integer value into the encoding
         The integer is associated with the given AttributeId annotation and the current open element.
        @param attribId is the given AttributeId annotation
        @param val is the unsigned integer value to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    @property
    def empty(self) -> bool: ...
import ghidra.program.model.address
import ghidra.program.model.pcode
import java.io
import java.lang


class Decoder(ghidra.program.model.pcode.ByteIngest, object):
    """
    An interface for reading structured data from a stream

     All data is loosely structured as with an XML document.  A document contains a nested set
     of elements, with labels corresponding to the ElementId class. A single element can hold
     zero or more attributes and zero or more child elements.  An attribute holds a primitive
     data element (boolean, long, String) and is labeled by an AttributeId. The document is traversed
     using a sequence of openElement() and closeElement() calls, intermixed with read*() calls to extract
     the data. The elements are traversed in a depth first order.  Attributes within an element can
     be traversed in order using repeated calls to the getNextAttributeId() method, followed by a calls to
     one of the read*(void) methods to extract the data.  Alternately a read*(AttributeId) call can be used
     to extract data for an attribute known to be in the element.  There is a special content attribute
     whose data can be extracted using a read*(AttributeId) call that is passed the special ATTRIB_CONTENT id.
     This attribute will not be traversed by getNextAttributeId().
    """









    def clear(self) -> None: ...

    def closeElement(self, id: int) -> None:
        """
        Close the current element
         The data for the current element is considered fully processed. If the element has additional
         children, an exception is thrown. The stream must indicate the end of the element in some way.
        @param id is the id of the element to close (which must be the current element)
        @throws DecoderException if not at end of expected element
        """
        ...

    def closeElementSkipping(self, id: int) -> None:
        """
        Close the current element, skipping any child elements that have not yet been parsed.
         This closes the given element, which must be current.  If there are child elements that have
         not been parsed, this is not considered an error, and they are skipped over in the parse.
        @param id is the id of the element to close (which must be the current element)
        @throws DecoderException if the indicated element is not the current element
        """
        ...

    def endIngest(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    def getClass(self) -> java.lang.Class: ...

    def getIndexedAttributeId(self, attribId: ghidra.program.model.pcode.AttributeId) -> int:
        """
        Get the id for the (current) attribute, assuming it is indexed.
         Assuming the previous call to getNextAttributeId() returned the id of ATTRIB_UNKNOWN,
         reinterpret the attribute as being an indexed form of the given attribute. If the attribute
         matches, return this indexed id, otherwise return ATTRIB_UNKNOWN.
        @param attribId is the attribute being indexed
        @return the indexed id or ATTRIB_UNKNOWN
        @throws DecoderException for unexpected end of stream
        """
        ...

    def getNextAttributeId(self) -> int:
        """
        Get the next attribute id for the current element
         Attributes are automatically set up for traversal using this method, when the element is
         opened. If all attributes have been traversed (or there are no attributes), 0 is returned.
        @return the id of the next attribute or 0
        @throws DecoderException for unexpected end of stream
        """
        ...

    def hashCode(self) -> int: ...

    def ingestStream(self, __a0: java.io.InputStream) -> None: ...

    def isEmpty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def open(self, __a0: int, __a1: unicode) -> None: ...

    @overload
    def openElement(self) -> int:
        """
        Open (traverse into) the next child element of the current parent.
         The child becomes the current parent.
         The list of attributes is initialized for use with getNextAttributeId.
        @return the id of the child element or 0 if there are no additional children
        @throws DecoderException for an unexpected end of stream
        """
        ...

    @overload
    def openElement(self, elemId: ghidra.program.model.pcode.ElementId) -> int:
        """
        Open (traverse into) the next child element, which must be of a specific type
         The child becomes the current parent, and its attributes are initialized for use with
         getNextAttributeId. The child must match the given element id or an exception is thrown.
        @param elemId is the given element id to match
        @return the id of the child element
        @throws DecoderException if the expected element is not the next element
        """
        ...

    def peekElement(self) -> int:
        """
        Peek at the next child element of the current parent, without traversing in (opening) it.
         The element id is returned, which can be compared to ElementId labels.
         If there are no remaining child elements to traverse, 0 is returned.
        @return the element id or 0
        @throws DecoderException for an unexpected end of stream
        """
        ...

    @overload
    def readBool(self) -> bool:
        """
        Parse the current attribute as a boolean value
         The last attribute, as returned by getNextAttributeId, is treated as a boolean, and its
         value is returned.
        @return the boolean value associated with the current attribute.
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readBool(self, attribId: ghidra.program.model.pcode.AttributeId) -> bool:
        """
        Find and parse a specific attribute in the current element as a boolean value
         The set of attributes for the current element is searched for a match to the given attribute
         id. This attribute is then parsed as a boolean and its value returned.
         If there is no attribute matching the id, an exception is thrown.
         Parsing via getNextAttributeId is reset.
        @param attribId is the specific attribute id to match
        @return the boolean value
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readSignedInteger(self) -> long:
        """
        Parse the current attribute as a signed integer value
         The last attribute, as returned by getNextAttributeId, is treated as a signed integer,
         and its value is returned.
        @return the signed integer value associated with the current attribute.
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readSignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId) -> long:
        """
        Find and parse a specific attribute in the current element as a signed integer
         The set of attributes for the current element is searched for a match to the given attribute
         id. This attribute is then parsed as a signed integer and its value returned.
         If there is no attribute matching the id, an exception is thrown.
         Parsing via getNextAttributeId is reset.
        @param attribId is the specific attribute id to match
        @return the signed integer value
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readSignedIntegerExpectString(self, expect: unicode, expectval: long) -> long:
        """
        Parse the current attribute as either a signed integer value or a string.
         If the attribute is an integer, its value is returned.
         If the attribute is a string, it must match an expected string passed to the method,
         and a predetermined integer value associated with the string is returned.
         If the attribute string does not match, or the attribute is encoded as anything other than
         a string or signed integer, an exception is thrown.
        @param expect is the string value to expect if the attribute is encoded as a string
        @param expectval is the integer value to return if the attribute matches the expected string
        @return the encoded integer or the integer value associated with the expected string
        @throws DecoderException is an integer value or expected string cannot be parsed
        """
        ...

    @overload
    def readSignedIntegerExpectString(self, attribId: ghidra.program.model.pcode.AttributeId, expect: unicode, expectval: long) -> long:
        """
        Find and parse a specific attribute in the current element as either a signed integer
         or a string. If the attribute is an integer, its value is returned.
         If the attribute is encoded as a string, it must match an expected string
         passed to this method. In this case, a predetermined integer value is passed back,
         indicating a matching string was parsed.  If the attribute string does not match, or
         the attribute is encoded as anything other than a string or signed integer, an exception
         is thrown.
        @param attribId is the specific attribute id to match
        @param expect is the string to expect, if the attribute is not encoded as an integer
        @param expectval is the integer value to return if the attribute matches the expected string
        @return the encoded integer or the integer value associated with the expected string
        @throws DecoderException if an integer value or expected string cannot be parsed
        """
        ...

    @overload
    def readSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Parse the current attribute as an address space
         The last attribute, as returned by getNextAttributeId, is returned as an address space.
        @return the address space associated with the current attribute.
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readSpace(self, attribId: ghidra.program.model.pcode.AttributeId) -> ghidra.program.model.address.AddressSpace:
        """
        Find the specific attribute in the current element and return it as an address space
         Search attributes from the current element for a match to the given attribute id.
         Return this attribute as an address space. If there is no attribute matching the id, an
         exception is thrown. Parse via getNextAttributeId is reset.
        @param attribId is the specific attribute id to match
        @return the address space associated with the attribute
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readString(self) -> unicode:
        """
        Parse the current attribute as a string
         The last attribute, as returned by getNextAttributeId, is returned as a string.
        @return the string associated with the current attribute.
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readString(self, attribId: ghidra.program.model.pcode.AttributeId) -> unicode:
        """
        Find the specific attribute in the current element and return it as a string
         The set of attributes for the current element is searched for a match to the given attribute
         id. This attribute is then returned as a string.  If there is no attribute matching the id,
         and exception is thrown. Parse via getNextAttributeId is reset.
        @param attribId is the specific attribute id to match
        @return the string associated with the attribute
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readUnsignedInteger(self) -> long:
        """
        Parse the current attribute as an unsigned integer value
         The last attribute, as returned by getNextAttributeId, is treated as an unsigned integer,
         and its value is returned.
        @return the unsigned integer value associated with the current attribute.
        @throws DecoderException if the expected value is not present
        """
        ...

    @overload
    def readUnsignedInteger(self, attribId: ghidra.program.model.pcode.AttributeId) -> long:
        """
        Find and parse a specific attribute in the current element as an unsigned integer
         The set of attributes for the current element is searched for a match to the given attribute
         id. This attribute is then parsed as an unsigned integer and its value returned.
         If there is no attribute matching the id, an exception is thrown.
         Parsing via getNextAttributeId is reset.
        @param attribId is the specific attribute id to match
        @return the unsigned integer value
        @throws DecoderException if the expected value is not present
        """
        ...

    def rewindAttributes(self) -> None:
        """
        Reset attribute traversal for the current element
         Attributes for a single element can be traversed more than once using the getNextAttributeId
         method.
        """
        ...

    def skipElement(self) -> None:
        """
        Skip parsing of the next element
         The element skipped is the one that would be opened by the next call to openElement.
        @throws DecoderException if there is no new element
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
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    @property
    def empty(self) -> bool: ...

    @property
    def nextAttributeId(self) -> int: ...
from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class AddressXML(object):
    """
    Utility class for the myriad ways of marshaling/unmarshaling an address and an optional size,
     to/from XML for the various configuration files.
 
     An object of the class itself is the most general form, where the specified address
       - MAY have an associated size given in bytes
       - MAY be in the JOIN address space, with physical pieces making up the logical value explicitly provided.
 
     The static buildXML methods write out an \ tag given component elements without allocating an object.
     The static readXML methods read XML tags (presented in different forms) and returns an Address object.
     The static appendAttributes methods write out attributes of an address to an arbitrary XML tag.
     The static restoreXML methods read an \ tag and produce a general AddressXML object.
    """

    MAX_PIECES: int



    @overload
    def __init__(self, spc: ghidra.program.model.address.AddressSpace, off: long, sz: int):
        """
        Construct an Address range as a space/offset/size
        @param spc is the address space containing the range
        @param off is the starting byte offset of the range
        @param sz is the size of the range in bytes
        """
        ...

    @overload
    def __init__(self, spc: ghidra.program.model.address.AddressSpace, off: long, sz: int, pieces: List[ghidra.program.model.pcode.Varnode]):
        """
        Construct a logical memory range, representing multiple ranges pieced together.
         The logical range is assigned an address in the JOIN address space.
         The physical pieces making up the logical range are passed in as a sequence of
         Varnodes representing, in order, the most significant through the least significant
         portions of the value.
        @param spc is the JOIN address space (must have a type of AddressSpace.TYPE_JOIN)
        @param off is the offset of the logical value within the JOIN space
        @param sz is the number of bytes in the logical value
        @param pieces is the array of 1 or more physical pieces
        """
        ...



    @staticmethod
    def decode(decoder: ghidra.program.model.pcode.Decoder) -> ghidra.program.model.address.Address:
        """
        Create an address from a stream encoding. This recognizes elements
           - \<addr>
           - \<spaceid>
           - \<iop> or
           - any element with "space" and "offset" attributes
 
         An empty \<addr> element, with no attributes, results in Address.NO_ADDRESS being returned.
        @param decoder is the stream decoder
        @return Address created from decode info
        @throws DecoderException for any problems decoding the stream
        """
        ...

    @staticmethod
    def decodeFromAttributes(decoder: ghidra.program.model.pcode.Decoder) -> ghidra.program.model.address.Address:
        """
        Create an address from "space" and "offset" attributes of the current element
        @param decoder is the stream decoder
        @return the decoded Address
        @throws DecoderException for any problems decoding the stream
        """
        ...

    @staticmethod
    def decodeStorageFromAttributes(size: int, decoder: ghidra.program.model.pcode.Decoder, pcodeFactory: ghidra.program.model.pcode.PcodeFactory) -> ghidra.program.model.listing.VariableStorage:
        """
        Decode a VariableStorage object from the attributes in the current address element.
         The start of storage corresponds to the decoded address. The size is either passed
         in or is decoded from a size attribute.
        @param size is the desired size of storage or -1 to use the size attribute
        @param decoder is the stream decoder
        @param pcodeFactory is used to resolve address spaces, etc.
        @return the decoded VariableStorage
        @throws DecoderException for any errors in the encoding or problems creating the storage
        """
        ...

    @overload
    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode this sized address as an \<addr> element to the stream
        @param encoder is the stream encoder
        @throws IOException for errors in the underlying stream
        """
        ...

    @overload
    @staticmethod
    def encode(encoder: ghidra.program.model.pcode.Encoder, addr: ghidra.program.model.address.Address) -> None:
        """
        Encode the given Address as an \<addr> element to the stream
        @param encoder is the stream encoder
        @param addr -- Address to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    @overload
    @staticmethod
    def encode(encoder: ghidra.program.model.pcode.Encoder, varnodes: List[ghidra.program.model.pcode.Varnode], logicalsize: long) -> None:
        """
        Encode a sequence of Varnodes as a single \<addr> element to the stream.
         If there is more than one Varnode, or if the logical size is non-zero,
         the \<addr> element will specify the address space as "join" and will have
         additional "piece" attributes.
        @param encoder is the stream encoder
        @param varnodes is the sequence of storage varnodes
        @param logicalsize is the logical size value of the varnode
        @throws IOException for errors in the underlying stream
        """
        ...

    @overload
    @staticmethod
    def encode(encoder: ghidra.program.model.pcode.Encoder, addr: ghidra.program.model.address.Address, size: int) -> None:
        """
        Encode the given Address and a size as an \<addr> element to the stream
        @param encoder is the stream encoder
        @param addr is the given Address
        @param size is the given size
        @throws IOException for errors in the underlying stream
        """
        ...

    @overload
    @staticmethod
    def encodeAttributes(encoder: ghidra.program.model.pcode.Encoder, addr: ghidra.program.model.address.Address) -> None:
        """
        Encode "space" and "offset" attributes for the current element, describing the
         given Address to the stream.
        @param encoder is the stream encoder
        @param addr is the given Address
        @throws IOException for errors in the underlying stream
        """
        ...

    @overload
    @staticmethod
    def encodeAttributes(encoder: ghidra.program.model.pcode.Encoder, addr: ghidra.program.model.address.Address, size: int) -> None:
        """
        Encode "space" "offset" and "size" attributes for the current element, describing
         the given memory range to the stream.
        @param encoder is the stream encoder
        @param addr is the starting Address of the memory range
        @param size is the size of the memory range
        @throws IOException for errors in the underlying stream
        """
        ...

    @overload
    @staticmethod
    def encodeAttributes(encoder: ghidra.program.model.pcode.Encoder, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> None:
        """
        Encode a memory range, as "space", "first", and "last" attributes, for the current element,
         to the stream.
        @param encoder is the stream encoder
        @param startAddr is the first address in the range
        @param endAddr is the last address in the range
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        @return the space associated of this address
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFirstAddress(self) -> ghidra.program.model.address.Address:
        """
        @return the first address in the range
        """
        ...

    def getJoinRecord(self) -> List[ghidra.program.model.pcode.Varnode]:
        """
        Get the array of physical pieces making up this logical address range, if
         the range is in the JOIN address space. Otherwise return null.
        @return the physical pieces or null
        """
        ...

    def getLastAddress(self) -> ghidra.program.model.address.Address:
        """
        @return the last address in the range
        """
        ...

    def getOffset(self) -> long:
        """
        @return the byte offset of this address
        """
        ...

    def getSize(self) -> long:
        """
        @return the size in bytes associated with this address
        """
        ...

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        Build a raw Varnode from the Address and size
        @return the new Varnode
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def restoreRangeXml(el: ghidra.xml.XmlElement, cspec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.pcode.AddressXML:
        """
        A memory range is read from attributes of an XML tag. The tag must either have:
            - "name" attribute - indicating a register 
            - "space" attribute - with optional "first" and "last" attributes
 
         With the "space" attribute, "first" defaults to 0 and "last" defaults to the last offset in the space.
        @param el is the XML element
        @param cspec is a compiler spec to resolve address spaces and registers
        @return an AddressXML object representing the range
        @throws XmlParseException if the XML is badly formed
        """
        ...

    @overload
    @staticmethod
    def restoreXml(el: ghidra.xml.XmlElement, cspec: ghidra.program.model.lang.CompilerSpec) -> ghidra.program.model.pcode.AddressXML:
        """
        Restore an Address (as an AddressSpace and an offset) and an optional size from XML tag.
         The tag can have any name, but it must either have:
            - A "name" attribute, indicating a register name  OR
            - A "space" and "offset" attribute, indicating the address space and offset
    
         If a register name is given, size is obtained from the register.  If an offset is
         given, the size can optionally be specified using a "size" attribute.
         If not explicitly described, the size is set to zero.
 
         This method supports the "join" address space attached to the compiler specification
        @param el is the XML tag
        @param cspec is the compiler spec for looking up registers
        @return an AddressXML object containing the recovered space,offset,size
        @throws XmlParseException for problems parsing
        """
        ...

    @overload
    @staticmethod
    def restoreXml(el: ghidra.xml.XmlElement, language: ghidra.program.model.lang.Language) -> ghidra.program.model.pcode.AddressXML:
        """
        Restore an Address (as an AddressSpace and an offset) and an optional size from XML tag.
         The tag can have any name, but it must either have:
            - A "name" attribute, indicating a register name  OR
            - A "space" and "offset" attribute, indicating the address space and offset
    
         If a register name is given, size is obtained from the register.  If an offset is
         given, the size can optionally be specified using a "size" attribute.
         If not explicitly described, the size is set to zero.
        @param el is the XML tag
        @param language is the processor language for looking up registers and address spaces
        @return an AddressXML object containing the recovered space,offset,size
        @throws XmlParseException for problems parsing
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
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def firstAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def joinRecord(self) -> List[ghidra.program.model.pcode.Varnode]: ...

    @property
    def lastAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def offset(self) -> long: ...

    @property
    def size(self) -> long: ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode: ...
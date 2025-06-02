from typing import Iterator
from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.program.model.pcode.Varnode
import java.lang


class VarnodeOperation(ghidra.program.model.pcode.Varnode):




    def __init__(self, pcodeOp: ghidra.program.model.pcode.PcodeOp, inputValues: List[ghidra.program.model.pcode.Varnode]): ...



    def contains(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Determine if this varnode contains the specified address
        @param addr the address for which to check
        @return true if this varnode contains the specified address
        """
        ...

    @staticmethod
    def decode(decoder: ghidra.program.model.pcode.Decoder, factory: ghidra.program.model.pcode.PcodeFactory) -> ghidra.program.model.pcode.Varnode:
        """
        Decode a Varnode from a stream
        @param decoder is the stream decoder
        @param factory pcode factory used to create valid pcode
        @return the new Varnode
        @throws DecoderException if the Varnode is improperly encoded
        """
        ...

    @staticmethod
    def decodePieces(decoder: ghidra.program.model.pcode.Decoder) -> ghidra.program.model.pcode.Varnode.Join:
        """
        Decode a sequence of Varnodes from "piece" attributes for the current open element.
         The Varnodes are normally associated with an Address in the "join" space. In this virtual
         space, a contiguous sequence of bytes, at a specific Address, represent a logical value
         that may physically be split across multiple registers or other storage locations.
        @param decoder is the stream decoder
        @return an array of decoded Varnodes and the logical size
        @throws DecoderException for any errors in the encoding
        """
        ...

    def encodePiece(self) -> unicode:
        """
        Encode details of the Varnode as a formatted string with three colon separated fields.
           space:offset:size
         The name of the address space, the offset of the address as a hex number, and
         the size field as a decimal number.
        @return the formatted String
        """
        ...

    def encodeRaw(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode just the raw storage info for this Varnode to stream
        @param encoder is the stream encoder
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, o: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        @return the address this varnode is attached to
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDef(self) -> ghidra.program.model.pcode.PcodeOp:
        """
        @return get the pcode op this varnode belongs to
        """
        ...

    def getDescendants(self) -> Iterator[ghidra.program.model.pcode.PcodeOp]:
        """
        @return iterator to all PcodeOp s that take this as input
        """
        ...

    def getHigh(self) -> ghidra.program.model.pcode.HighVariable:
        """
        @return the high level variable this varnode represents
        """
        ...

    def getInputValues(self) -> List[ghidra.program.model.pcode.Varnode]: ...

    def getLoneDescend(self) -> ghidra.program.model.pcode.PcodeOp:
        """
        If there is only one PcodeOp taking this varnode as input, return it. Otherwise return null
        @return the lone descendant PcodeOp
        """
        ...

    def getMergeGroup(self) -> int:
        """
        @return the index of the group, within the high containing this, that are forced merged with this
        """
        ...

    def getOffset(self) -> long:
        """
        @return the offset into the address space varnode is defined within
        """
        ...

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address where this varnode is defined or
         NO_ADDRESS if this varnode is an input
        @return the address
        """
        ...

    def getPCodeOp(self) -> ghidra.program.model.pcode.PcodeOp: ...

    def getSize(self) -> int:
        """
        @return size of the varnode in bytes
        """
        ...

    def getSpace(self) -> int:
        """
        @return the space this varnode belongs to (ram, register, ...)
        """
        ...

    def getWordOffset(self) -> long:
        """
        Returns the word offset into the address space this is defined within
 
         The word size is defined in the Language's .slaspec file with the
         "WORDSIZE" argument when DEFINEing a memory SPACE (capitalization is
         for emphasis; the directives are actually lowercase).
        @return the word offset into the address space this is defined within
        """
        ...

    def hashCode(self) -> int: ...

    @overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Determine if this varnode intersects the specified address set
        @param set address set
        @return true if this varnode intersects the specified address set
        """
        ...

    @overload
    def intersects(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Determine if this varnode intersects another varnode.
        @param varnode other varnode
        @return true if this varnode intersects the specified varnode
        """
        ...

    def isAddrTied(self) -> bool: ...

    def isAddress(self) -> bool: ...

    def isConstant(self) -> bool: ...

    def isFree(self) -> bool: ...

    def isHash(self) -> bool: ...

    def isInput(self) -> bool: ...

    def isPersistent(self) -> bool: ...

    def isRegister(self) -> bool: ...

    def isSimplified(self) -> bool: ...

    def isUnaffected(self) -> bool: ...

    def isUnique(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setSimplified(self, simplified: bool) -> None: ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    def toString(self, language: ghidra.program.model.lang.Language) -> unicode: ...

    def trim(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def PCodeOp(self) -> ghidra.program.model.pcode.PcodeOp: ...

    @property
    def addrTied(self) -> bool: ...

    @property
    def address(self) -> bool: ...

    @property
    def constant(self) -> bool: ...

    @property
    def free(self) -> bool: ...

    @property
    def input(self) -> bool: ...

    @property
    def inputValues(self) -> List[ghidra.program.model.pcode.Varnode]: ...

    @property
    def persistent(self) -> bool: ...

    @property
    def register(self) -> bool: ...

    @property
    def simplified(self) -> bool: ...

    @simplified.setter
    def simplified(self, value: bool) -> None: ...

    @property
    def unaffected(self) -> bool: ...

    @property
    def unique(self) -> bool: ...
from typing import Iterator
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.program.model.pcode.Varnode
import java.lang


class VarnodeAST(ghidra.program.model.pcode.Varnode):
    """
    This type of Varnode is a node in an Abstract Syntax Tree
     It keeps track of its defining PcodeOp (in-edge) and PcodeOps which use it (out-edges)
    """





    def __init__(self, a: ghidra.program.model.address.Address, sz: int, id: int): ...



    def addDescendant(self, op: ghidra.program.model.pcode.PcodeOp) -> None: ...

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

    def descendReplace(self, vn: ghidra.program.model.pcode.VarnodeAST) -> None:
        """
        Replace all of parameter vn's references with this
        @param vn Varnode whose references will get replaced
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

    def getDef(self) -> ghidra.program.model.pcode.PcodeOp: ...

    def getDescendants(self) -> Iterator[ghidra.program.model.pcode.PcodeOp]: ...

    def getHigh(self) -> ghidra.program.model.pcode.HighVariable: ...

    def getLoneDescend(self) -> ghidra.program.model.pcode.PcodeOp: ...

    def getMergeGroup(self) -> int: ...

    def getOffset(self) -> long:
        """
        @return the offset into the address space varnode is defined within
        """
        ...

    def getPCAddress(self) -> ghidra.program.model.address.Address: ...

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

    def getUniqueId(self) -> int: ...

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

    def isAddress(self) -> bool:
        """
        @return true if this varnode exists in a Memory space (vs. register etc...).
         Keep in mind this varnode may also correspond to a defined register 
         if true is returned and {@link #isRegister()} return false.  
         Memory-based registers may be indirectly addressed which leads to the 
         distinction with registers within the register space.
        """
        ...

    def isConstant(self) -> bool:
        """
        @return true if this varnode is just a constant number
        """
        ...

    def isFree(self) -> bool: ...

    def isHash(self) -> bool: ...

    def isInput(self) -> bool: ...

    def isPersistent(self) -> bool: ...

    def isRegister(self) -> bool:
        """
        @return true if this varnode exists in a Register type space.
         If false is returned, keep in mind this varnode may still correspond to a 
         defined register within a memory space.  Memory-based registers may be indirectly 
         addressed which leads to the distinction with registers within the register space.
        """
        ...

    def isUnaffected(self) -> bool: ...

    def isUnique(self) -> bool:
        """
        @return true if this varnode doesn't exist anywhere.  A temporary variable.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeDescendant(self, op: ghidra.program.model.pcode.PcodeOp) -> None: ...

    def setAddrtied(self, val: bool) -> None: ...

    def setDef(self, op: ghidra.program.model.pcode.PcodeOp) -> None: ...

    def setFree(self, val: bool) -> None: ...

    def setHigh(self, hi: ghidra.program.model.pcode.HighVariable) -> None: ...

    def setInput(self, val: bool) -> None: ...

    def setMergeGroup(self, val: int) -> None: ...

    def setPersistent(self, val: bool) -> None: ...

    def setUnaffected(self, val: bool) -> None: ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    def toString(self, language: ghidra.program.model.lang.Language) -> unicode:
        """
        Convert this varnode to an alternate String representation based on a specified language.
        @param language is the specified Language
        @return string representation
        """
        ...

    def trim(self) -> None:
        """
        Trim a varnode in a constant space to the correct starting offset.
 
         Constant handles may contain constants of indeterminate size.
         This is where the size gets fixed, i.e. we mask off the constant
         to its proper size.  A varnode that is ends up in pcode should
         call this method to ensure that varnodes always contains raw data.
         On the other hand, varnodes in handles are allowed to have offsets
         that violate size restrictions.
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def PCAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def addrTied(self) -> bool: ...

    @property
    def addrtied(self) -> None: ...  # No getter available.

    @addrtied.setter
    def addrtied(self, value: bool) -> None: ...

    @property
    def def(self) -> ghidra.program.model.pcode.PcodeOp: ...

    @def.setter
    def def(self, value: ghidra.program.model.pcode.PcodeOp) -> None: ...

    @property
    def descendants(self) -> java.util.Iterator: ...

    @property
    def free(self) -> bool: ...

    @free.setter
    def free(self, value: bool) -> None: ...

    @property
    def high(self) -> ghidra.program.model.pcode.HighVariable: ...

    @high.setter
    def high(self, value: ghidra.program.model.pcode.HighVariable) -> None: ...

    @property
    def input(self) -> bool: ...

    @input.setter
    def input(self, value: bool) -> None: ...

    @property
    def loneDescend(self) -> ghidra.program.model.pcode.PcodeOp: ...

    @property
    def mergeGroup(self) -> int: ...

    @mergeGroup.setter
    def mergeGroup(self, value: int) -> None: ...

    @property
    def persistent(self) -> bool: ...

    @persistent.setter
    def persistent(self, value: bool) -> None: ...

    @property
    def unaffected(self) -> bool: ...

    @unaffected.setter
    def unaffected(self, value: bool) -> None: ...

    @property
    def uniqueId(self) -> int: ...
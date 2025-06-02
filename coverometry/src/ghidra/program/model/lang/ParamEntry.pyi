from typing import List
import ghidra.app.plugin.processors.sleigh
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class ParamEntry(object):
    TYPE_FLOAT: int = 3
    TYPE_PTR: int = 2
    TYPE_UNKNOWN: int = 8



    def __init__(self, grp: int): ...



    def containedBy(self, addr: ghidra.program.model.address.Address, sz: int) -> bool:
        """
        Is this ParamEntry, as a memory range, contained by the given memory range.
        @param addr is the starting address of the given memory range
        @param sz is the number of bytes in the given memory range
        @return true if this is contained
        """
        ...

    def contains(self, otherEntry: ghidra.program.model.lang.ParamEntry) -> bool:
        """
        Does this ParamEntry contain another entry (as a subpiece)
        @param otherEntry is the other entry
        @return true if this contains the other entry
        """
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddrBySlot(self, slotnum: int, sz: int, res: ghidra.app.plugin.processors.sleigh.VarnodeData) -> int:
        """
        Return the storage address assigned when allocating something of size -sz- assuming -slotnum- slots
         have already been assigned.  Set res.space to null if the -sz- is too small or if
         there are not enough slots left
        @param slotnum number of slots already assigned
        @param sz number of bytes to being assigned
        @param res the final storage address
        @return slotnum plus the number of slots used
        """
        ...

    def getAddressBase(self) -> long: ...

    def getAlign(self) -> int: ...

    def getAllGroups(self) -> List[int]: ...

    def getClass(self) -> java.lang.Class: ...

    def getGroup(self) -> int: ...

    def getJoinPieces(self, sz: int) -> List[ghidra.program.model.pcode.Varnode]:
        """
        Collect pieces from the join list, in endian order, until the given size is covered.
         The last piece is trimmed to match the size exactly.  If the size is too big to be
         covered by this ParamEntry, null is returned.
        @param sz is the given size
        @return the collected array of Varnodes or null
        """
        ...

    @staticmethod
    def getMetatype(tp: ghidra.program.model.data.DataType) -> int: ...

    def getMinSize(self) -> int: ...

    def getSize(self) -> int: ...

    def getSlot(self, addr: ghidra.program.model.address.Address, skip: int) -> int:
        """
        Assuming the address is contained in this entry and we -skip- to a certain byte
         return the slot associated with that byte
        @param addr is the address to check (which MUST be contained)
        @param skip is the number of bytes to skip
        @return the slot index
        """
        ...

    def getSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def getType(self) -> int: ...

    def hashCode(self) -> int: ...

    def intersects(self, addr: ghidra.program.model.address.Address, sz: int) -> bool:
        """
        Does this ParamEntry intersect the given range in some way
        @param addr is the starting address of the given range
        @param sz is the number of bytes in the given range
        @return true if there is an intersection
        """
        ...

    def isBigEndian(self) -> bool: ...

    def isEquivalent(self, obj: ghidra.program.model.lang.ParamEntry) -> bool:
        """
        Determine if this ParamEntry is equivalent to another instance
        @param obj is the other instance
        @return true if they are equivalent
        """
        ...

    def isExclusion(self) -> bool: ...

    def isFloatExtended(self) -> bool: ...

    def isGrouped(self) -> bool: ...

    def isOverlap(self) -> bool: ...

    def isReverseStack(self) -> bool: ...

    def justifiedContain(self, addr: ghidra.program.model.address.Address, sz: int) -> int: ...

    @staticmethod
    def justifiedContainAddress(spc1: ghidra.program.model.address.AddressSpace, offset1: long, sz1: int, spc2: ghidra.program.model.address.AddressSpace, offset2: long, sz2: int, forceleft: bool, isBigEndian: bool) -> int:
        """
        Return -1 if (op2,sz2) is not properly contained in (op1,sz1)
         If it is contained, return the endian aware offset of (op2,sz2)
         I.e. if the least significant byte of the op2 range falls on the least significant
         byte of the op1 range, return 0.  If it intersects the second least significant, return 1, etc.
        @param spc1 the first address space
        @param offset1 the first offset
        @param sz1 size of first space
        @param spc2 the second address space
        @param offset2 is the second offset
        @param sz2 size of second space
        @param forceleft is true if containment is forced to be on the left even for big endian
        @param isBigEndian true if big endian
        @return the endian aware offset or -1
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def orderWithinGroup(entry1: ghidra.program.model.lang.ParamEntry, entry2: ghidra.program.model.lang.ParamEntry) -> None:
        """
        ParamEntry within a group must be distinguishable by size or by type
        @param entry1 is the first being compared
        @param entry2 is the second being compared
        @throws XmlParseException if the pair is not distinguishable
        """
        ...

    def restoreXml(self, __a0: ghidra.xml.XmlPullParser, __a1: ghidra.program.model.lang.CompilerSpec, __a2: List[object], __a3: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressBase(self) -> long: ...

    @property
    def align(self) -> int: ...

    @property
    def allGroups(self) -> List[int]: ...

    @property
    def bigEndian(self) -> bool: ...

    @property
    def exclusion(self) -> bool: ...

    @property
    def floatExtended(self) -> bool: ...

    @property
    def group(self) -> int: ...

    @property
    def grouped(self) -> bool: ...

    @property
    def minSize(self) -> int: ...

    @property
    def overlap(self) -> bool: ...

    @property
    def reverseStack(self) -> bool: ...

    @property
    def size(self) -> int: ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def type(self) -> int: ...
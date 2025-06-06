from typing import List
import ghidra.program.database
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class DataOrganizationImpl(object, ghidra.program.model.data.DataOrganization):
    """
    DataOrganization provides a single place for determining size and alignment information
     for data types within an archive or a program.
    """

    DEFAULT_CHAR_IS_SIGNED: bool = True
    DEFAULT_CHAR_SIZE: int = 1
    DEFAULT_DEFAULT_ALIGNMENT: int = 1
    DEFAULT_DEFAULT_POINTER_ALIGNMENT: int = 4
    DEFAULT_DOUBLE_SIZE: int = 8
    DEFAULT_FLOAT_SIZE: int = 4
    DEFAULT_INT_SIZE: int = 4
    DEFAULT_LONG_DOUBLE_SIZE: int = 8
    DEFAULT_LONG_LONG_SIZE: int = 8
    DEFAULT_LONG_SIZE: int = 4
    DEFAULT_MACHINE_ALIGNMENT: int = 8
    DEFAULT_POINTER_SHIFT: int = 0
    DEFAULT_POINTER_SIZE: int = 4
    DEFAULT_SHORT_SIZE: int = 2
    DEFAULT_WIDE_CHAR_SIZE: int = 2
    NO_MAXIMUM_ALIGNMENT: int = 0







    def clearSizeAlignmentMap(self) -> None:
        """
        Remove all entries from the size alignment map
        """
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Output the details of this data organization to a encoded document formatter.
        @param encoder the output document encoder.
        @throws IOException if an IO error occurs while encoding/writing output
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def getAbsoluteMaxAlignment(self) -> int:
        """
        Gets the maximum alignment value that is allowed by this data organization. When getting
         an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
         is returned, the data organization isn't specifically limited.
        @return the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
        """
        ...

    @staticmethod
    def getAlignedOffset(alignment: int, minimumOffset: int) -> int:
        """
        Determines the first offset that is equal to or greater than the minimum offset which
         has the specified alignment.  If a non-positive alignment is specified the origina
         minimumOffset will be return.
        @param alignment the desired alignment (positive value)
        @param minimumOffset the minimum offset
        @return the aligned offset
        """
        ...

    def getAlignment(self, dataType: ghidra.program.model.data.DataType) -> int: ...

    def getBitFieldPacking(self) -> ghidra.program.model.data.BitFieldPacking: ...

    def getCharSize(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultAlignment(self) -> int:
        """
        Gets the default alignment to be used for any data type that isn't a
         structure, union, array, pointer, type definition, and whose size isn't in the
         size/alignment map.
        @return the default alignment to be used if no other alignment can be
         determined for a data type.
        """
        ...

    @overload
    @staticmethod
    def getDefaultOrganization() -> ghidra.program.model.data.DataOrganization:
        """
        Creates a new default DataOrganization. This has a mapping which defines the alignment
         of a data type based on its size. The map defines pairs for data types that are
         1, 2, 4, and 8 bytes in length.
        @return a new default DataOrganization.
        """
        ...

    @overload
    @staticmethod
    def getDefaultOrganization(language: ghidra.program.model.lang.Language) -> ghidra.program.model.data.DataOrganizationImpl:
        """
        Creates a new default DataOrganization. This has a mapping which defines the alignment
         of a data type based on its size. The map defines pairs for data types that are
         1, 2, 4, and 8 bytes in length.
        @param language optional language used to initialize defaults (pointer size, endianess, etc.)
          (may be null)
        @return a new default DataOrganization.
        """
        ...

    def getDefaultPointerAlignment(self) -> int:
        """
        Gets the default alignment to be used for a pointer that doesn't have size.
        @return the default alignment for a pointer
        """
        ...

    def getDoubleSize(self) -> int: ...

    def getFloatSize(self) -> int: ...

    @staticmethod
    def getGreatestCommonDenominator(value1: int, value2: int) -> int:
        """
        Determines the greatest common denominator of two numbers.
        @param value1 the first number
        @param value2 the second number
        @return the greatest common denominator
        """
        ...

    def getIntegerCTypeApproximation(self, size: int, signed: bool) -> unicode:
        """
        Returns the best fitting integer C-type whose size is less-than-or-equal
         to the specified size.  "long long" will be returned for any size larger
         than "long long";
        @param size integer size
        @param signed if false the unsigned modifier will be prepended.
        @return the best fitting
        """
        ...

    def getIntegerSize(self) -> int: ...

    @staticmethod
    def getLeastCommonMultiple(value1: int, value2: int) -> int:
        """
        Determines the least (lowest) common multiple of two numbers.
        @param value1 the first number
        @param value2 the second number
        @return the least common multiple
        """
        ...

    def getLongDoubleSize(self) -> int: ...

    def getLongLongSize(self) -> int: ...

    def getLongSize(self) -> int: ...

    def getMachineAlignment(self) -> int:
        """
        Gets the maximum useful alignment for the target machine
        @return the machine alignment
        """
        ...

    def getPointerShift(self) -> int: ...

    def getPointerSize(self) -> int: ...

    def getShortSize(self) -> int: ...

    def getSizeAlignment(self, size: int) -> int: ...

    def getSizeAlignmentCount(self) -> int:
        """
        Gets the number of sizes that have an alignment specified.
        @return the number of sizes with an alignment mapped to them.
        """
        ...

    def getSizes(self) -> List[int]:
        """
        Gets the sizes that have an alignment specified.
        @return the sizes with alignments mapped to them.
        """
        ...

    def getWideCharSize(self) -> int: ...

    def hashCode(self) -> int: ...

    def isBigEndian(self) -> bool: ...

    def isEquivalent(self, __a0: ghidra.program.model.data.DataOrganization) -> bool: ...

    def isSignedChar(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def restore(dataMap: ghidra.program.database.DBStringMapAdapter, keyPrefix: unicode) -> ghidra.program.model.data.DataOrganizationImpl:
        """
        Restore a data organization from the specified DB data map.
        @param dataMap DB data map
        @param keyPrefix key prefix for all map entries
        @return stored data organization or null if not stored
        @throws IOException if an IO error occurs
        """
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser) -> None:
        """
        Restore settings from an XML stream. This expects to see parser positioned on the
         &lt;data_organization&gt; start tag.  The XML is designed to override existing language-specific
         default settings which are pre-populated with {@link #getDefaultOrganization(Language)}.  This
         will will ensure that the endianess setting is properly established since it is not included
         in the XML.
        @param parser is the XML stream
        """
        ...

    @staticmethod
    def save(dataOrg: ghidra.program.model.data.DataOrganization, dataMap: ghidra.program.database.DBStringMapAdapter, keyPrefix: unicode) -> None:
        """
        Save the specified data organization to the specified DB data map.
         All existing map entries starting with keyPrefix will be removed prior
         to ading the new map entries.
        @param dataOrg data organization
        @param dataMap DB data map
        @param keyPrefix key prefix for all map entries
        @throws IOException if an IO error occurs
        """
        ...

    def setAbsoluteMaxAlignment(self, absoluteMaxAlignment: int) -> None:
        """
        Sets the maximum alignment value that is allowed by this data organization. When getting
         an alignment for any data type it will not exceed this value. If NO_MAXIMUM_ALIGNMENT
         is returned, the data organization isn't specifically limited.
        @param absoluteMaxAlignment the absolute maximum alignment or NO_MAXIMUM_ALIGNMENT
        """
        ...

    def setBigEndian(self, bigEndian: bool) -> None:
        """
        Set data endianess
        @param bigEndian true if big-endian, false if little-endian
        """
        ...

    def setBitFieldPacking(self, bitFieldPacking: ghidra.program.model.data.BitFieldPackingImpl) -> None:
        """
        Set the bitfield packing information associated with this data organization.
        @param bitFieldPacking bitfield packing information
        """
        ...

    def setCharIsSigned(self, signed: bool) -> None:
        """
        Defines the signed-ness of the "char" data type
        @param signed true if "char" type is signed
        """
        ...

    def setCharSize(self, charSize: int) -> None:
        """
        Defines the size of a char (char) data type.
        @param charSize the size of a char (char).
        """
        ...

    def setDefaultAlignment(self, defaultAlignment: int) -> None:
        """
        Sets the default alignment to be used for any data type that isn't a
         structure, union, array, pointer, type definition, and whose size isn't in the
         size/alignment map.
        @param defaultAlignment the default alignment to be used if no other alignment can be
         determined for a data type.
        """
        ...

    def setDefaultPointerAlignment(self, defaultPointerAlignment: int) -> None:
        """
        Sets the default alignment to be used for a pointer that doesn't have size.
        @param defaultPointerAlignment the default alignment for a pointer
        """
        ...

    def setDoubleSize(self, doubleSize: int) -> None:
        """
        Defines the encoding size of a double primitive data type.
        @param doubleSize the size of a double.
        """
        ...

    def setFloatSize(self, floatSize: int) -> None:
        """
        Defines the encoding size of a float primitive data type.
        @param floatSize the size of a float.
        """
        ...

    def setIntegerSize(self, integerSize: int) -> None:
        """
        Defines the size of an int primitive data type.
        @param integerSize the size of an int.
        """
        ...

    def setLongDoubleSize(self, longDoubleSize: int) -> None:
        """
        Defines the encoding size of a long double primitive data type.
        @param longDoubleSize the size of a long double.
        """
        ...

    def setLongLongSize(self, longLongSize: int) -> None:
        """
        Defines the size of a long long primitive data type.
        @param longLongSize the size of a long long.
        """
        ...

    def setLongSize(self, longSize: int) -> None:
        """
        Defines the size of a long primitive data type.
        @param longSize the size of a long.
        """
        ...

    def setMachineAlignment(self, machineAlignment: int) -> None:
        """
        Sets the maximum useful alignment for the target machine
        @param machineAlignment the machine alignment
        """
        ...

    def setPointerShift(self, pointerShift: int) -> None:
        """
        Defines the left shift amount for a shifted pointer data type.
         Shift amount affects interpretation of in-memory pointer values only
         and will also be reflected within instruction pcode.
        @param pointerShift left shift amount for in-memory pointer values
        """
        ...

    def setPointerSize(self, pointerSize: int) -> None:
        """
        Defines the size of a pointer data type.
        @param pointerSize the size of a pointer.
        """
        ...

    def setShortSize(self, shortSize: int) -> None:
        """
        Defines the size of a short primitive data type.
        @param shortSize the size of a short.
        """
        ...

    def setSizeAlignment(self, size: int, alignment: int) -> None:
        """
        Sets the alignment that is defined for a data type of the indicated size if one is defined.
        @param size the size of the data type
        @param alignment the alignment of the data type.
        """
        ...

    def setWideCharSize(self, wideCharSize: int) -> None:
        """
        Defines the size of a wide-char (wchar_t) data type.
        @param wideCharSize the size of a wide-char (wchar_t).
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
    def absoluteMaxAlignment(self) -> int: ...

    @absoluteMaxAlignment.setter
    def absoluteMaxAlignment(self, value: int) -> None: ...

    @property
    def bigEndian(self) -> bool: ...

    @bigEndian.setter
    def bigEndian(self, value: bool) -> None: ...

    @property
    def bitFieldPacking(self) -> ghidra.program.model.data.BitFieldPacking: ...

    @property
    def charIsSigned(self) -> None: ...  # No getter available.

    @charIsSigned.setter
    def charIsSigned(self, value: bool) -> None: ...

    @property
    def charSize(self) -> int: ...

    @charSize.setter
    def charSize(self, value: int) -> None: ...

    @property
    def defaultAlignment(self) -> int: ...

    @defaultAlignment.setter
    def defaultAlignment(self, value: int) -> None: ...

    @property
    def defaultPointerAlignment(self) -> int: ...

    @defaultPointerAlignment.setter
    def defaultPointerAlignment(self, value: int) -> None: ...

    @property
    def doubleSize(self) -> int: ...

    @doubleSize.setter
    def doubleSize(self, value: int) -> None: ...

    @property
    def floatSize(self) -> int: ...

    @floatSize.setter
    def floatSize(self, value: int) -> None: ...

    @property
    def integerSize(self) -> int: ...

    @integerSize.setter
    def integerSize(self, value: int) -> None: ...

    @property
    def longDoubleSize(self) -> int: ...

    @longDoubleSize.setter
    def longDoubleSize(self, value: int) -> None: ...

    @property
    def longLongSize(self) -> int: ...

    @longLongSize.setter
    def longLongSize(self, value: int) -> None: ...

    @property
    def longSize(self) -> int: ...

    @longSize.setter
    def longSize(self, value: int) -> None: ...

    @property
    def machineAlignment(self) -> int: ...

    @machineAlignment.setter
    def machineAlignment(self, value: int) -> None: ...

    @property
    def pointerShift(self) -> int: ...

    @pointerShift.setter
    def pointerShift(self, value: int) -> None: ...

    @property
    def pointerSize(self) -> int: ...

    @pointerSize.setter
    def pointerSize(self, value: int) -> None: ...

    @property
    def shortSize(self) -> int: ...

    @shortSize.setter
    def shortSize(self, value: int) -> None: ...

    @property
    def signedChar(self) -> bool: ...

    @property
    def sizeAlignmentCount(self) -> int: ...

    @property
    def sizes(self) -> List[int]: ...

    @property
    def wideCharSize(self) -> int: ...

    @wideCharSize.setter
    def wideCharSize(self, value: int) -> None: ...
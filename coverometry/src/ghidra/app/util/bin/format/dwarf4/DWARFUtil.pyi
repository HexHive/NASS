from typing import List
import generic.jar
import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf4
import ghidra.app.util.bin.format.dwarf4.DWARFUtil
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import java.lang
import java.lang.reflect


class DWARFUtil(object):





    class LengthResult(object):
        format: int
        length: long







        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self): ...



    @staticmethod
    def appendComment(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, commentType: int, prefix: unicode, comment: unicode, sep: unicode) -> None: ...

    @overload
    @staticmethod
    def appendDescription(dt: ghidra.program.model.data.DataType, description: unicode, sep: unicode) -> None:
        """
        Append a string to a {@link DataType}'s description.
        @param dt {@link DataType}
        @param description string to append, if null or empty nothing happens.
        @param sep characters to place after previous description to separate it from the
         new portion.
        """
        ...

    @overload
    @staticmethod
    def appendDescription(dtc: ghidra.program.model.data.DataTypeComponent, description: unicode, sep: unicode) -> None:
        """
        Append a string to a description of a field in a structure.
        @param dtc the {@link DataTypeComponent field} in a struct
        @param description string to append, if null or empty nothing happens.
        @param sep characters to place after previous description to separate it from the
         new portion.
        """
        ...

    @staticmethod
    def convertRegisterListToVarnodeStorage(__a0: List[object], __a1: int) -> List[object]: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findLinkageNameInChildren(die: ghidra.app.util.bin.format.dwarf4.DebugInfoEntry) -> List[unicode]:
        """
        Try to find gnu mangled name nesting info in a DIE's children's linkage strings.
         <p>
        @param die
        @return a list of string of nesting names, ending with what should be the DIE parameter's
         name.
        """
        ...

    @staticmethod
    def getAnonNameForMeFromParentContext(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> unicode:
        """
        Creates a name for anon types based on their position in their parent's childList.
         <p>
        @param diea the die aggregate.
        @return the anonymous name of the die aggregate.
        """
        ...

    @staticmethod
    def getAnonNameForMeFromParentContext2(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> unicode:
        """
        Creates a name for anon types based on the names of sibling entries that are using the anon type.
         <p>
         Example: "anon_struct_for_field1_field2"
         <p>
         Falls back to {@link #getAnonNameForMeFromParentContext(DIEAggregate)} if no siblings found.
        @param diea the die aggregate.
        @return the anonymous name of the die aggregate.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getCodeUnitForComment(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.CodeUnit: ...

    @staticmethod
    def getContainerTypeName(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> unicode:
        """
        Returns a string that describes what kind of object is specified by the {@link DIEAggregate}.
         <p>
         Used to create a name for anonymous types.
        @param diea {@link DIEAggregate}
        @return String describing the type of the DIEA.
        """
        ...

    @staticmethod
    def getLanguageDefinitionDirectory(lang: ghidra.program.model.lang.Language) -> generic.jar.ResourceFile:
        """
        Returns the base directory of a language definition.
        @param lang {@link Language} to get base definition directory
        @return base directory for language definition files
        @throws IOException
        """
        ...

    @staticmethod
    def getLanguageExternalFile(lang: ghidra.program.model.lang.Language, name: unicode) -> generic.jar.ResourceFile:
        """
        Returns a file that has been referenced in the specified {@link Language language's}
         ldefs description via a
         <pre>&lt;external_name tool="<b>name</b>" name="<b>value</b>"/&gt;</pre>
         entry.
        @param lang {@link Language} to query
        @param name name of the option in the ldefs file
        @return file pointed to by the specified external_name tool entry
        @throws IOException
        """
        ...

    @staticmethod
    def getLanguageExternalNameValue(lang: ghidra.program.model.lang.Language, name: unicode) -> unicode:
        """
        Returns a value specified in a {@link Language} definition via a
         <pre>&lt;external_name tool="<b>name</b>" name="<b>value</b>"/&gt;</pre>
         entry.
         <p>
        @param lang {@link Language} to query
        @param name name of the value
        @return String value
        @throws IOException
        """
        ...

    @staticmethod
    def getLexicalBlockName(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> unicode:
        """
        Create a name for a lexical block, with "_" separated numbers indicating nesting
         information of the lexical block.
        @param diea {@link DIEAggregate} pointing to a lexical block entry.
        @return string, ie. "lexical_block_1_2_3"
        """
        ...

    @staticmethod
    def getMyPositionInParent(die: ghidra.app.util.bin.format.dwarf4.DebugInfoEntry) -> int:
        """
        Returns the ordinal position of this {@link DebugInfoEntry} in it's parent.
        @param die {@link DebugInfoEntry}
        @return int index of ourself in our parent, or -1 if not found in parent.
        """
        ...

    @staticmethod
    def getReferringTypedef(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> ghidra.app.util.bin.format.dwarf4.DIEAggregate:
        """
        Returns the {@link DIEAggregate} of a typedef that points to the specified datatype.
         <p>
         Returns null if there is no typedef pointing to the specified DIEA or if there are
         multiple.
        @param diea {@link DIEAggregate} of a data type that might be the target of typedefs.
        @return {@link DIEAggregate} of the singular typedef that points to the arg, otherwise
         null if none or multiple found.
        """
        ...

    @staticmethod
    def getStaticFinalFieldWithValue(clazz: java.lang.Class, value: long) -> java.lang.reflect.Field:
        """
        Searches a Class for a final static variable that has a specific numeric value.
        @param clazz Class to search.
        @param value numeric value to search for
        @return Java reflection {@link Field} that has the specified value or null
        """
        ...

    @staticmethod
    def getStructLayoutFingerprint(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> unicode:
        """
        Creates a fingerprint of the layout of an (anonymous) structure using its
         size, number of members, and the hashcode of the member field names.
        @param diea struct/union/class
        @return formatted string, example "80_5_73dc6de9" (80 bytes, 5 fields, hex hash of field names)
        """
        ...

    @staticmethod
    def getSymbolTypeFromDIE(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> ghidra.program.model.symbol.SymbolType:
        """
        Returns the {@link SymbolType} that corresponds to the specified {@link DIEAggregate}.
         <p>
         The mapping between DIE type and SymbolType is not exact.  There is no matching
         SymbolType for a DWARF static variable, so "LOCAL_VAR" is used currently.
         <p>
         This mainly is used in constructing a NamespacePath, and the only critical usage
         there is Namespace vs. Class vs. everything else.
        @param diea {@link DIEAggregate} to query
        @return {@link SymbolType}
        """
        ...

    @staticmethod
    def getTemplateBaseName(name: unicode) -> unicode:
        """
        Determines if a name is a C++ style templated name.  If so, returns just
         the base portion of the name.
         The name must have a start and end angle bracket: '&lt;' and '&gt;'.
         <p>
         operator&lt;() and operator&lt;&lt;() are handled so their angle brackets
         don't trigger the template start/end angle bracket incorrectly.
         <p>
        @param name symbol name with C++ template portions
        @return base portion of the symbol name without template portion
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isEmptyArray(dt: ghidra.program.model.data.DataType) -> bool: ...

    @staticmethod
    def isPointerDataType(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> bool: ...

    @staticmethod
    def isPointerTo(targetDIEA: ghidra.app.util.bin.format.dwarf4.DIEAggregate, testDIEA: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> bool: ...

    @staticmethod
    def isStackVarnode(varnode: ghidra.program.model.pcode.Varnode) -> bool: ...

    @staticmethod
    def isThisParam(paramDIEA: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> bool: ...

    @staticmethod
    def isVoid(dt: ghidra.program.model.data.DataType) -> bool: ...

    @staticmethod
    def isZeroByteDataType(dt: ghidra.program.model.data.DataType) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def packCompositeIfPossible(original: ghidra.program.model.data.Composite, dtm: ghidra.program.model.data.DataTypeManager) -> None: ...

    @staticmethod
    def parseMangledNestings(s: unicode) -> List[unicode]:
        """
        A lightweight attempt to get nesting (ie. namespaces and such) information
         from gnu mangled name strings.
         <p>
         For example, "_ZN19class1_inline_funcs3fooEv" -&gt;
         [19 chars]'class1_inline_funcs', [3 chars]'foo'
         <p>
        @param s
        @return 
        """
        ...

    @staticmethod
    def readAddressAsLong(reader: ghidra.app.util.bin.BinaryReader, pointerSize: int) -> long:
        """
        Reads a variable-sized unsigned 'address' value from a {@link BinaryReader} and
         returns it as a 64 bit java long.
         <p>
         The valid pointerSizes are 1, 2, 4, and 8.
         <p>
        @param reader {@link BinaryReader} to read the data from
        @param pointerSize number of bytes the value is stored in, must be 1, 2, 4, or 8.
        @return unsigned long value.
        @throws IOException if error
        """
        ...

    @staticmethod
    def readLength(reader: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.dwarf4.DWARFUtil.LengthResult:
        """
        Read a variable-length length value from the stream.
         <p>
        @param reader {@link BinaryReader} stream to read from
        @param program Ghidra {@link Program}
        @return new {@link LengthResult}, never null; length == 0 should be checked for and treated
         specially
        @throws IOException if io error
        @throws DWARFException if invalid values
        """
        ...

    @staticmethod
    def readOffsetByDWARFformat(reader: ghidra.app.util.bin.BinaryReader, dwarfFormat: int) -> long:
        """
        Read an offset value who's size depends on the DWARF format: 32 vs 64.
         <p>
        @param reader BinaryReader pointing to the value to read
        @param dwarfFormat - See {@link DWARFCompilationUnit#DWARF_32} and {@link DWARFCompilationUnit#DWARF_64}.
        @return the offset value
        @throws IOException if an I/O error occurs or bad dwarfFormat value
        """
        ...

    @staticmethod
    def readVarSizedUInt(reader: ghidra.app.util.bin.BinaryReader, size: int) -> int:
        """
        Read a variable-sized unsigned integer and return it as a java signed int.
         <p>
         Unsigned 32 bit int values larger than java's signed Integer.MAX_VALUE are not
         supported and will throw an IOException.
        @param reader {@link BinaryReader} to read the data from
        @param size number of bytes the integer value is stored in, must be 1, 2 or 4.
        @return unsigned integer value.
        @throws IOException if error
        """
        ...

    @staticmethod
    def readVarSizedULong(reader: ghidra.app.util.bin.BinaryReader, pointerSize: int) -> long:
        """
        Read a variable-sized unsigned integer and return it as a java signed long.
         <p>
        @param reader {@link BinaryReader} to read the data from
        @param pointerSize number of bytes the value is stored in, must be 1, 2, 4, or 8.
        @return unsigned long integer value.
        @throws IOException if error
        """
        ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def toString(clazz: java.lang.Class, value: long) -> unicode:
        """
        Returns the field name of a final static variable in class <code>clazz</code>
         which holds a specific value.
         <p>
         Can be thought of as an enum numeric value to to name lookup.
         <p>
        @param clazz
        @param value
        @return 
        """
        ...

    @overload
    @staticmethod
    def toString(clazz: java.lang.Class, value: int) -> unicode:
        """
        Converts a integer value to its corresponding symbolic name from the set of
         "public static final" member variables in a class.
         <p>
         This is a bit of a hack and probably originated from pre-java Enum days.
        @param clazz The {@link Class} to search for the matching static value.
        @param value the integer value to search for
        @return the String name of the matching field.
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


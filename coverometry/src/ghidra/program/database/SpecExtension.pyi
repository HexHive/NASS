from typing import List
import generic.stl
import ghidra.program.database
import ghidra.program.database.SpecExtension
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.task
import java.lang
import java.util


class SpecExtension(object):
    """
    Utility class for installing/removing "specification extensions" to a Program.
     A specification extension is a program specific version of either a:
       - Prototype Model
       - Call Fixup or 
       - Callother Fixup
     Normally these objects are provided by the language specific configuration files (.cspec or .pspec),
     but this class allows additional objects to be added that are specific to the program.
 
     Internally, each spec extension is stored as an XML document as a formal Program Option. Each type of
     extension is described by a specific XML tag and is parsed as it would be in a .cspec or .pspec file.
     The XML tags are:
       - \        - describing a Call Fixup
       - \   - describing a Callother Fixup
       - \        - describing a typical Prototype Model
       - \ - describing a Prototype Model merged from other models
   
     Each type of object has a unique name or target, which must be specified as part of the XML tag,
     which is referred to in this class as the extension's "formal name".  In the \ tag,
     the formal name is given by the "targetop" attribute; for all the other tags, the formal name is
     given by the "name" attribute".
 
     The parent option for all extensions is given by the static field SPEC_EXTENSION. Under the parent
     option, each extension is stored as a string with an option name, constructed by
     concatenating the extension's formal name with a prefix corresponding to the extension's XML tag name.

     testExtensionDocument() is used independently to extensively test whether a document
     describes a valid extension.
 
     Extensions are installed on a program via addReplaceCompilerSpecExtension().
     Extensions are removed from a program via removeCompilerSpecExtension().
    """

    FORMAT_VERSION: int = 1
    FORMAT_VERSION_OPTIONNAME: unicode = u'FormatVersion'
    SPEC_EXTENSION: unicode = u'Specification Extensions'
    VERSION_COUNTER_OPTIONNAME: unicode = u'VersionCounter'




    class DocInfo(object):




        def __init__(self, __a0: unicode): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getFormalName(self) -> unicode: ...

        def getOptionName(self) -> unicode: ...

        def getType(self) -> ghidra.program.database.SpecExtension.Type: ...

        def hashCode(self) -> int: ...

        def isOverride(self) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def formalName(self) -> unicode: ...

        @property
        def optionName(self) -> unicode: ...

        @property
        def override(self) -> bool: ...

        @property
        def type(self) -> ghidra.program.database.SpecExtension.Type: ...




    class Type(java.lang.Enum):
        CALLOTHER_FIXUP: ghidra.program.database.SpecExtension.Type = CALLOTHER_FIXUP
        CALL_FIXUP: ghidra.program.database.SpecExtension.Type = CALL_FIXUP
        MERGE_MODEL: ghidra.program.database.SpecExtension.Type = MERGE_MODEL
        PROTOTYPE_MODEL: ghidra.program.database.SpecExtension.Type = PROTOTYPE_MODEL







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def getOptionName(self, __a0: unicode) -> unicode: ...

        def getTagName(self) -> unicode: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.program.database.SpecExtension.Type: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.program.database.SpecExtension.Type]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def tagName(self) -> unicode: ...

    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Construct an extension manager attached to a specific program.
         Multiple add/remove/test actions can be performed.  Validator state is cached between calls.
        @param program is the specific Program
        """
        ...



    def addReplaceCompilerSpecExtension(self, document: unicode, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Install or replace a spec extension to the program.  The extension is presented as
         an XML document, from which a name is extracted.  If an extension previously existed
         with the same name, it is overwritten.  Otherwise the document is treated as a new
         extension.  Testing is performed before installation:
            - Document is parsed as XML and is verified against spec grammars
            - Internal p-code tags from InjectPayloads are compiled
            - Name collisions are checked for
        @param document is the XML document describing the extension
        @param monitor is a task monitor
        @throws LockException if the caller does not exclusive access to the program
        @throws XmlParseException for a badly formed extension document
        @throws SAXException for parse errors in the extension document
        @throws SleighException for a document that fails verification
        """
        ...

    @staticmethod
    def checkFormatVersion(program: ghidra.program.model.listing.Program) -> None:
        """
        Check the format version for spec extensions for a given program.
         If the program reports a version that does not match the current
         number attached to the running tool (FORMAT_VERSION), a VersionException is thrown
        @param program is the given Program
        @throws VersionException the reported version does not match the tool
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getCompilerSpecExtension(program: ghidra.program.model.listing.Program, type: ghidra.program.database.SpecExtension.Type, name: unicode) -> unicode:
        """
        Get the raw string making up an extension, given its type and name
        @param program is the program to extract the extension from
        @param type is the type of extension
        @param name is the formal name of the extension
        @return the extension string or null
        """
        ...

    @staticmethod
    def getCompilerSpecExtensions(program: ghidra.program.model.listing.Program) -> List[generic.stl.Pair]:
        """
        Get all compiler spec extensions for the program. The extensions are XML documents
         strings, with an associated "option name" string.
         Return a list of (optionname,document) pairs, which may be empty
        @param program is the Program to get extensions for
        @return the list of (optionname,document) pairs
        """
        ...

    @staticmethod
    def getExtensionType(nm: unicode, isXML: bool) -> ghidra.program.database.SpecExtension.Type:
        """
        Get the extension type either from the XML tag name or the option name
        @param nm is the XML tag or option name
        @param isXML is true for an XML tag, false for an option name
        @return the extension type
        @throws SleighException if no type matches the name
        """
        ...

    @staticmethod
    def getFormalName(optionName: unicode) -> unicode:
        """
        Get the formal name of an extension from its option name.
        @param optionName is the option name
        @return the formal name
        """
        ...

    @staticmethod
    def getVersionCounter(program: ghidra.program.model.listing.Program) -> int:
        """
        Get version of CompilerSpec extensions stored with the Program
        @param program is the given Program
        @return the version number
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isValidFormalName(formalName: unicode) -> bool:
        """
        Determine if the desired formal name is a valid identifier
        @param formalName is the formal name to check
        @return true if the name is valid
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parseExtension(optionName: unicode, extension: unicode, cspec: ghidra.program.model.lang.CompilerSpec, provideDummy: bool) -> object:
        """
        Parse an XML string and build the corresponding compiler spec extension object.
         Currently this can either be a
            - PrototypeModel or
            - InjectPayload
 
         For InjectPayloadCallfixup or InjectPayloadCallother, the p-code \<body> tag
         is also parsed, and the caller can control whether any parse errors
         cause an exception or whether a dummy payload is provided instead.
        @param optionName is the option name the extension is attached to
        @param extension is the XML document as a String
        @param cspec is the compiler spec the new extension is for
        @param provideDummy if true, provide a dummy payload if necessary
        @return the extension object
        @throws SAXException is there are XML format errors
        @throws XmlParseException if the XML document is badly formed
        @throws SleighException if internal p-code does not parse
        """
        ...

    @staticmethod
    def registerOptions(program: ghidra.program.model.listing.Program) -> None:
        """
        Register the options system allowing spec extensions with the given Program
        @param program is the given Program
        """
        ...

    def removeCompilerSpecExtension(self, optionName: unicode, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Remove the indicated spec extension from the program.
         Depending on the type, references to the extension are removed or altered
         first, to facilitate final removal of the extension.
         All changes are made in a single transaction that can be cancelled.
        @param optionName is the option name where the extension is stored
        @param monitor is a provided monitor that can trigger cancellation
        @throws LockException if the caller does not have exclusive access to the program
        @throws CancelledException if the caller cancels the operation via the task monitor
        """
        ...

    def testExtensionDocument(self, document: unicode) -> ghidra.program.database.SpecExtension.DocInfo:
        """
        Test if the given XML document describes a suitable spec extension.
         The document must fully parse and validate and must not conflict with the existing spec;
         otherwise an exception is thrown. If all tests pass, an object describing basic properties
         of the document is returned.
        @param document is the given XML document
        @return info about the document
        @throws SleighException if validity checks fail
        @throws XmlParseException if the XML is badly formed
        @throws SAXException if there are parse errors
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


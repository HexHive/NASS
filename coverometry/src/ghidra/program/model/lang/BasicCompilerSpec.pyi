from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang
import java.util


class BasicCompilerSpec(object, ghidra.program.model.lang.CompilerSpec):
    """
    BasicCompilerSpec implements the CompilerSpec interface based on static information
     from a particular .cspec file.  Typically the .cspec file is read in once by a Language
     object whenever a new or opened Program indicates a particular language and compiler.
     The BasicCompilerSpec is owned by the Language and (parts of it) may be reused by
     multiple Programs.
    """

    CALLING_CONVENTION_cdecl: unicode = u'__cdecl'
    CALLING_CONVENTION_default: unicode = u'default'
    CALLING_CONVENTION_fastcall: unicode = u'__fastcall'
    CALLING_CONVENTION_pascal: unicode = u'__pascal'
    CALLING_CONVENTION_stdcall: unicode = u'__stdcall'
    CALLING_CONVENTION_thiscall: unicode = u'__thiscall'
    CALLING_CONVENTION_unknown: unicode = u'unknown'
    CALLING_CONVENTION_vectorcall: unicode = u'__vectorcall'



    @overload
    def __init__(self, op2: ghidra.program.model.lang.BasicCompilerSpec):
        """
        Clone the spec so that program can safely extend it without affecting the base
         spec from Language.
        @param op2 is the spec to clone
        """
        ...

    @overload
    def __init__(self, description: ghidra.program.model.lang.CompilerSpecDescription, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, cspecFile: generic.jar.ResourceFile):
        """
        Read in the specification from an XML file.
        @param description is the .ldefs description associated with the specification
        @param language is the language owning the specification
        @param cspecFile is the XML file
        @throws CompilerSpecNotFoundException for any form of error preventing the specification from being loaded.
        """
        ...

    @overload
    def __init__(self, description: ghidra.program.model.lang.CompilerSpecDescription, language: ghidra.app.plugin.processors.sleigh.SleighLanguage, stream: java.io.InputStream):
        """
        Construct the specification from an XML stream.  This is currently only used for testing.
        @param description is the .ldefs description matching this specification
        @param language is the language that owns the specification
        @param stream is the XML stream
        @throws XmlParseException for badly formed XML
        @throws SAXException for syntax errors in the XML
        @throws IOException for errors accessing the stream
        @throws DuplicateNameException if there exists more than one PrototypeModel with the same name
        """
        ...



    def applyContextSettings(self, programContext: ghidra.program.model.listing.DefaultProgramContext) -> None: ...

    def doesCDataTypeConversions(self) -> bool: ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def findBestCallingConvention(self, params: List[ghidra.program.model.listing.Parameter]) -> ghidra.program.model.lang.PrototypeModel: ...

    def getAddressSpace(self, spaceName: unicode) -> ghidra.program.model.address.AddressSpace: ...

    def getAllModels(self) -> List[ghidra.program.model.lang.PrototypeModel]: ...

    def getCallingConvention(self, name: unicode) -> ghidra.program.model.lang.PrototypeModel: ...

    def getCallingConventions(self) -> List[ghidra.program.model.lang.PrototypeModel]: ...

    def getClass(self) -> java.lang.Class: ...

    def getCompilerSpecDescription(self) -> ghidra.program.model.lang.CompilerSpecDescription: ...

    def getCompilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID: ...

    def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    def getDecompilerOutputLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage: ...

    def getDefaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getLanguage(self) -> ghidra.program.model.lang.Language: ...

    def getPcodeInjectLibrary(self) -> ghidra.program.model.lang.PcodeInjectLibrary: ...

    @overload
    def getProperty(self, key: unicode) -> unicode: ...

    @overload
    def getProperty(self, key: unicode, defaultString: unicode) -> unicode: ...

    def getPropertyAsBoolean(self, key: unicode, defaultBoolean: bool) -> bool: ...

    def getPropertyAsInt(self, key: unicode, defaultInt: int) -> int: ...

    def getPropertyKeys(self) -> java.util.Set: ...

    def getPrototypeEvaluationModel(self, modelType: ghidra.program.model.lang.CompilerSpec.EvaluationModelType) -> ghidra.program.model.lang.PrototypeModel: ...

    def getStackBaseSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def getStackPointer(self) -> ghidra.program.model.lang.Register: ...

    def getStackSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def hasProperty(self, key: unicode) -> bool: ...

    def hashCode(self) -> int: ...

    def isEquivalent(self, obj: ghidra.program.model.lang.CompilerSpec) -> bool: ...

    def isGlobal(self, addr: ghidra.program.model.address.Address) -> bool: ...

    def isStackRightJustified(self) -> bool: ...

    def matchConvention(self, conventionName: unicode) -> ghidra.program.model.lang.PrototypeModel: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def stackGrowsNegative(self) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def allModels(self) -> List[ghidra.program.model.lang.PrototypeModel]: ...

    @property
    def callingConventions(self) -> List[ghidra.program.model.lang.PrototypeModel]: ...

    @property
    def compilerSpecDescription(self) -> ghidra.program.model.lang.CompilerSpecDescription: ...

    @property
    def compilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID: ...

    @property
    def dataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    @property
    def decompilerOutputLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage: ...

    @property
    def defaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def language(self) -> ghidra.program.model.lang.Language: ...

    @property
    def pcodeInjectLibrary(self) -> ghidra.program.model.lang.PcodeInjectLibrary: ...

    @property
    def propertyKeys(self) -> java.util.Set: ...

    @property
    def stackBaseSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def stackPointer(self) -> ghidra.program.model.lang.Register: ...

    @property
    def stackRightJustified(self) -> bool: ...

    @property
    def stackSpace(self) -> ghidra.program.model.address.AddressSpace: ...
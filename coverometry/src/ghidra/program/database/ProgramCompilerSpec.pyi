from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang
import java.util


class ProgramCompilerSpec(ghidra.program.model.lang.BasicCompilerSpec):
    """
    A Program-specific version of the CompilerSpec.
 
     Every Program owns a specific . It is based on a
     CompilerSpec returned by the Language assigned to the Program, but it may
     include extensions. Extensions are currently either a new form of:
 
 
     PrototypeModel or
     InjectPayload
 
 
     Extensions can be installed or removed from a ProgramDB via the Options mechanism
     (See SpecExtension) using
     SpecExtension#addReplaceCompilerSpecExtension(String, TaskMonitor) or
     SpecExtension#removeCompilerSpecExtension(String, TaskMonitor).
 
      allows the static evaluation models, described by the underlying
     BasicCompilerSpec and returned by
     #getPrototypeEvaluationModel(EvaluationModelType), to be overridden by Program-specific
     options.
 
     #getDecompilerOutputLanguage() queries the Program-specific language the decompiler
     should use as output.
 
     #installExtensions() is the main entry point for integrating the Program Options with the
     Language's base CompilerSpec and producing a complete in-memory CompilerSpec for the Program.
    """

    DECOMPILER_OUTPUT_DEF: ghidra.program.model.lang.DecompilerLanguage = c-language
    DECOMPILER_OUTPUT_DESC: unicode = u'Select the source language output by the decompiler.'
    DECOMPILER_OUTPUT_LANGUAGE: unicode = u'Output Language'
    DECOMPILER_PROPERTY_LIST_NAME: unicode = u'Decompiler'
    EVALUATION_MODEL_PROPERTY_NAME: unicode = u'Prototype Evaluation'







    def applyContextSettings(self, programContext: ghidra.program.model.listing.DefaultProgramContext) -> None: ...

    def doesCDataTypeConversions(self) -> bool: ...

    @staticmethod
    def enableJavaLanguageDecompilation(program: ghidra.program.model.listing.Program) -> None:
        """
        Adds and enables an option to have the decompiler display java.
        @param program to be enabled
        """
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None: ...

    def equals(self, obj: object) -> bool: ...

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
    def decompilerOutputLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage: ...
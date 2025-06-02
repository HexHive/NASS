from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang
import java.util


class CompilerSpec(object):
    """
    Interface for requesting specific information about the compiler used to
     build a Program being analyzed.  Major elements that can be queried include:
       - AddressSpaces from the Language plus compiler specific ones like "stack"
       - DataOrganization describing size and alignment of primitive data-types: int, long, pointers, etc.
       - PrototypeModels describing calling conventions used by the compiler: __stdcall, __thiscall, etc.
       - InjectPayloads or p-code that can used for
          - Call-fixups, substituting p-code for compiler bookkeeping functions during analysis.
          - Callother-fixups, substituting p-code for user-defined p-code operations.
       - Memory ranges that the compiler treats as global
       - Context and register values known to the compiler over specific memory ranges
    """

    CALLING_CONVENTION_cdecl: unicode = u'__cdecl'
    CALLING_CONVENTION_default: unicode = u'default'
    CALLING_CONVENTION_fastcall: unicode = u'__fastcall'
    CALLING_CONVENTION_pascal: unicode = u'__pascal'
    CALLING_CONVENTION_stdcall: unicode = u'__stdcall'
    CALLING_CONVENTION_thiscall: unicode = u'__thiscall'
    CALLING_CONVENTION_unknown: unicode = u'unknown'
    CALLING_CONVENTION_vectorcall: unicode = u'__vectorcall'




    class EvaluationModelType(java.lang.Enum):
        EVAL_CALLED: ghidra.program.model.lang.CompilerSpec.EvaluationModelType = EVAL_CALLED
        EVAL_CURRENT: ghidra.program.model.lang.CompilerSpec.EvaluationModelType = EVAL_CURRENT







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.program.model.lang.CompilerSpec.EvaluationModelType: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.program.model.lang.CompilerSpec.EvaluationModelType]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def applyContextSettings(self, ctx: ghidra.program.model.listing.DefaultProgramContext) -> None:
        """
        Apply context settings to the ProgramContext
         as specified by the configuration
        @param ctx is the ProgramContext
        """
        ...

    def doesCDataTypeConversions(self) -> bool:
        """
        Return true if function prototypes respect the C-language data-type conversion conventions.
         This amounts to converting array data-types to pointer-to-element data-types.
         In C, arrays are passed by reference (structures are still passed by value)
        @return if the prototype does C-language data-type conversions
        """
        ...

    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode this entire specification to a stream.  A document is written with
         root element \<compiler_spec>.
        @param encoder is the stream encoder
        @throws IOException for errors writing to the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def findBestCallingConvention(self, params: List[ghidra.program.model.listing.Parameter]) -> ghidra.program.model.lang.PrototypeModel:
        """
        Find the best guess at a calling convention model from this compiler spec
         given an ordered list of (potential) parameters with storage assignments.
        @param params is the ordered list of parameters
        @return prototype model corresponding to the specified function signature
        """
        ...

    def getAddressSpace(self, spaceName: unicode) -> ghidra.program.model.address.AddressSpace:
        """
        Get an address space by name.  This can be value added over the normal AddressFactory.getAddressSpace
         routine because the compiler spec can refer to special internal spaces like the stack space
        @param spaceName is the name of the address space
        @return the corresponding AddressSpace object
        """
        ...

    def getAllModels(self) -> List[ghidra.program.model.lang.PrototypeModel]:
        """
        @return all possible PrototypeModels, including calling conventions and merge models
        """
        ...

    def getCallingConvention(self, name: unicode) -> ghidra.program.model.lang.PrototypeModel:
        """
        Returns the Calling Convention Model with the given name.
        @param name the name of the calling convention to retrieve
        @return the calling convention with the given name or null if there is none with that name.
        """
        ...

    def getCallingConventions(self) -> List[ghidra.program.model.lang.PrototypeModel]:
        """
        @return an array of the prototype models. Each prototype model specifies a calling convention.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCompilerSpecDescription(self) -> ghidra.program.model.lang.CompilerSpecDescription:
        """
        @return a brief description of the compiler spec
        """
        ...

    def getCompilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID:
        """
        @return the id string associated with this compiler spec;
        """
        ...

    def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    def getDecompilerOutputLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage:
        """
        Get the language that the decompiler produces
        @return an enum specifying the language
        """
        ...

    def getDefaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        Returns the prototype model that is the default calling convention or else null.
        @return the default calling convention or null.
        """
        ...

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the Language this compiler spec is based on.  Note that
         compiler specs may be reused across multiple languages in the
         cspec files on disk, but once loaded in memory are actually
         separate objects.  (M:N on disk, 1:N in memory)
        @return the language this compiler spec is based on
        """
        ...

    def getPcodeInjectLibrary(self) -> ghidra.program.model.lang.PcodeInjectLibrary: ...

    @overload
    def getProperty(self, key: unicode) -> unicode:
        """
        Gets a property defined for this language, or null if that property isn't defined.
        @param key the property key
        @return the property value, or null if not defined
        """
        ...

    @overload
    def getProperty(self, key: unicode, defaultString: unicode) -> unicode:
        """
        Gets the value of a property as a String, returning defaultString if undefined.
        @param key the property key
        @param defaultString the default value to return if property is undefined
        @return the property value as a String, or the default value if undefined
        """
        ...

    def getPropertyAsBoolean(self, key: unicode, defaultBoolean: bool) -> bool:
        """
        Gets the value of a property as a boolean, returning defaultBoolean if undefined.
        @param key the property key
        @param defaultBoolean the default value to return if property is undefined
        @return the property value as a boolean, or the default value if undefined
        """
        ...

    def getPropertyAsInt(self, key: unicode, defaultInt: int) -> int:
        """
        Gets the value of a property as an int, returning defaultInt if undefined.
        @param key the property key
        @param defaultInt the default value to return if property is undefined
        @return the property value as an int, or the default value if undefined
        """
        ...

    def getPropertyKeys(self) -> java.util.Set:
        """
        Returns a read-only set view of the property keys defined on this language.
        @return read-only set of property keys
        """
        ...

    def getPrototypeEvaluationModel(self, modelType: ghidra.program.model.lang.CompilerSpec.EvaluationModelType) -> ghidra.program.model.lang.PrototypeModel:
        """
        Get the evaluation model matching the given type.
         If analysis needs to apply a PrototypeModel to a function but a specific model
         is not known, then this method can be used to select a putative PrototypeModel
         based on the analysis use-case:
            - EVAL_CURRENT indicates the model to use for the "current function" being analyzed
            - EVAL_CALLED indicates the model to use for a function called by the current function
        @param modelType is the type of evaluation model
        @return prototype evaluation model
        """
        ...

    def getStackBaseSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the physical space used for stack data storage
        @return address space which contains the stack
        """
        ...

    def getStackPointer(self) -> ghidra.program.model.lang.Register:
        """
        Get the default Stack Pointer register for this language if there is one.
        @return default stack pointer register.
        """
        ...

    def getStackSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Get the stack address space defined by this specification
        @return stack address space
        """
        ...

    def hasProperty(self, key: unicode) -> bool:
        """
        Returns whether this language has a property defined.
        @param key the property key
        @return if the property is defined
        """
        ...

    def hashCode(self) -> int: ...

    def isEquivalent(self, obj: ghidra.program.model.lang.CompilerSpec) -> bool:
        """
        Determine if this CompilerSpec is equivalent to another specified instance
        @param obj is the other instance
        @return true if they are equivalent
        """
        ...

    def isGlobal(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        @param addr is the (start of the) storage location
        @return true if the specified storage location has been designated "global" in scope
        """
        ...

    def isStackRightJustified(self) -> bool:
        """
        Indicates whether variables are right-justified within the 
         stack alignment.
        @return true if right stack justification applies.
        """
        ...

    def matchConvention(self, conventionName: unicode) -> ghidra.program.model.lang.PrototypeModel:
        """
        Get the PrototypeModel which corresponds to the given calling convention name.
         If no match is found the default prototype model is returned.
        @param conventionName calling convention name.
        @return the matching model or the defaultModel if nothing matches
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def stackGrowsNegative(self) -> bool:
        """
        @return true if the stack grows with negative offsets
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
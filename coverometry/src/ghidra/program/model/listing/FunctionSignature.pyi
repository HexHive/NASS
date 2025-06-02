from typing import List
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang


class FunctionSignature(object):
    """
    Interface describing all the things about a function that are portable
     from one program to another.
    """

    NORETURN_DISPLAY_STRING: unicode = u'noreturn'
    VAR_ARGS_DISPLAY_STRING: unicode = u'...'
    VOID_PARAM_DISPLAY_STRING: unicode = u'void'







    def equals(self, __a0: object) -> bool: ...

    def getArguments(self) -> List[ghidra.program.model.data.ParameterDefinition]:
        """
        Get function signature parameter arguments
        @return an array of parameters for the function
        """
        ...

    def getCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        Gets the calling convention prototype model for this function if associated with a 
         compiler specificfation.  This method will always return null if signature is not 
         associated with a specific program architecture.
        @return the prototype model of the function's current calling convention or null.
        """
        ...

    def getCallingConventionName(self) -> unicode:
        """
        Returns the calling convention name associated with this function definition.
         Reserved names may also be returned: {@link Function#UNKNOWN_CALLING_CONVENTION_STRING},
         {@link Function#DEFAULT_CALLING_CONVENTION_STRING}.
         The "unknown" convention must be returned instead of null.
        @return calling convention name
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self) -> unicode:
        """
        Get descriptive comment for signature
        @return the comment string
        """
        ...

    def getName(self) -> unicode:
        """
        Return the name of this function
        """
        ...

    @overload
    def getPrototypeString(self) -> unicode:
        """
        Get string representation of the function signature without the
         calling convention specified.
        @return function signature string
        """
        ...

    @overload
    def getPrototypeString(self, includeCallingConvention: bool) -> unicode:
        """
        Get string representation of the function signature
        @param includeCallingConvention if true prototype will include call convention
         declaration if known as well as <code>noreturn</code> indicator if applicable.
        @return function signature string
        """
        ...

    def getReturnType(self) -> ghidra.program.model.data.DataType:
        """
        Get function signature return type
        @return the return data type
        """
        ...

    def hasNoReturn(self) -> bool:
        """
        @return true if this function signature corresponds to a non-returning function.
        """
        ...

    def hasUnknownCallingConventionName(self) -> bool:
        """
        Determine if this signature has an unknown or unrecognized calling convention name.
        @return true if calling convention is unknown or unrecognized name, else false.
        """
        ...

    def hasVarArgs(self) -> bool:
        """
        @return true if this function signature has a variable argument list (VarArgs).
        """
        ...

    def hashCode(self) -> int: ...

    def isEquivalentSignature(self, signature: ghidra.program.model.listing.FunctionSignature) -> bool:
        """
        Returns true if the given signature is equivalent to this signature.  The
         precise meaning of "equivalent" is dependent upon return/parameter dataTypes.
        @param signature the function signature being tested for equivalence.
        @return true if the if the given signature is equivalent to this signature.
        """
        ...

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
    def arguments(self) -> List[ghidra.program.model.data.ParameterDefinition]: ...

    @property
    def callingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def callingConventionName(self) -> unicode: ...

    @property
    def comment(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @property
    def prototypeString(self) -> unicode: ...

    @property
    def returnType(self) -> ghidra.program.model.data.DataType: ...
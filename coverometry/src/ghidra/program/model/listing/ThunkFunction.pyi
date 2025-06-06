from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang
import java.util


class ThunkFunction(ghidra.program.model.listing.Function, object):
    """
    ThunkFunction corresponds to a fragment of code which simply passes control
     to a destination function.  All Function behaviors are mapped through to the current
     destination function.
    """

    DEFAULT_CALLING_CONVENTION_STRING: unicode = u'default'
    DEFAULT_LOCAL_PREFIX: unicode = u'local_'
    DEFAULT_LOCAL_PREFIX_LEN: int = 6
    DEFAULT_LOCAL_RESERVED_PREFIX: unicode = u'local_res'
    DEFAULT_LOCAL_TEMP_PREFIX: unicode = u'temp_'
    DEFAULT_PARAM_PREFIX: unicode = u'param_'
    DEFAULT_PARAM_PREFIX_LEN: int = 6
    DELIMITER: unicode = u'::'
    GLOBAL_NAMESPACE_ID: long = 0x0L
    INLINE: unicode = u'inline'
    INVALID_STACK_DEPTH_CHANGE: int = 2147483646
    NAMESPACE_DELIMITER: unicode = u'::'
    NORETURN: unicode = u'noreturn'
    RETURN_PTR_PARAM_NAME: unicode = u'__return_storage_ptr__'
    THIS_PARAM_NAME: unicode = u'this'
    THUNK: unicode = u'thunk'
    UNKNOWN_CALLING_CONVENTION_STRING: unicode = u'unknown'
    UNKNOWN_STACK_DEPTH_CHANGE: int = 2147483647







    def addLocalVariable(self, __a0: ghidra.program.model.listing.Variable, __a1: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Variable: ...

    def addParameter(self, __a0: ghidra.program.model.listing.Variable, __a1: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Parameter: ...

    def addTag(self, __a0: unicode) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getAllVariables(self) -> List[ghidra.program.model.listing.Variable]: ...

    def getAutoParameterCount(self) -> int: ...

    def getBody(self) -> ghidra.program.model.address.AddressSetView: ...

    def getCallFixup(self) -> unicode: ...

    def getCalledFunctions(self, __a0: ghidra.util.task.TaskMonitor) -> java.util.Set: ...

    def getCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getCallingConventionName(self) -> unicode: ...

    def getCallingFunctions(self, __a0: ghidra.util.task.TaskMonitor) -> java.util.Set: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self) -> unicode: ...

    def getCommentAsArray(self) -> List[unicode]: ...

    def getDestinationFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        """
        Returns the current destination function entry point address.
         A function should exist at the specified address although there is no guarantee.
         If the address is within the EXTERNAL space, this a place-holder for a an external
         library function.
        @return destination function entry point address
        """
        ...

    def getEntryPoint(self) -> ghidra.program.model.address.Address: ...

    def getExternalLocation(self) -> ghidra.program.model.symbol.ExternalLocation: ...

    @overload
    def getFunctionThunkAddresses(self) -> List[ghidra.program.model.address.Address]: ...

    @overload
    def getFunctionThunkAddresses(self, __a0: bool) -> List[ghidra.program.model.address.Address]: ...

    def getID(self) -> long: ...

    @overload
    def getLocalVariables(self) -> List[ghidra.program.model.listing.Variable]: ...

    @overload
    def getLocalVariables(self, __a0: ghidra.program.model.listing.VariableFilter) -> List[ghidra.program.model.listing.Variable]: ...

    @overload
    def getName(self) -> unicode: ...

    @overload
    def getName(self, __a0: bool) -> unicode: ...

    def getParameter(self, __a0: int) -> ghidra.program.model.listing.Parameter: ...

    def getParameterCount(self) -> int: ...

    @overload
    def getParameters(self) -> List[ghidra.program.model.listing.Parameter]: ...

    @overload
    def getParameters(self, __a0: ghidra.program.model.listing.VariableFilter) -> List[ghidra.program.model.listing.Parameter]: ...

    def getParentNamespace(self) -> ghidra.program.model.symbol.Namespace: ...

    def getPathList(self, __a0: bool) -> List[object]: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getPrototypeString(self, __a0: bool, __a1: bool) -> unicode: ...

    def getRepeatableComment(self) -> unicode: ...

    def getRepeatableCommentAsArray(self) -> List[unicode]: ...

    def getReturn(self) -> ghidra.program.model.listing.Parameter: ...

    def getReturnType(self) -> ghidra.program.model.data.DataType: ...

    @overload
    def getSignature(self) -> ghidra.program.model.listing.FunctionSignature: ...

    @overload
    def getSignature(self, __a0: bool) -> ghidra.program.model.listing.FunctionSignature: ...

    def getSignatureSource(self) -> ghidra.program.model.symbol.SourceType: ...

    def getStackFrame(self) -> ghidra.program.model.listing.StackFrame: ...

    def getStackPurgeSize(self) -> int: ...

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    def getTags(self) -> java.util.Set: ...

    def getThunkedFunction(self, __a0: bool) -> ghidra.program.model.listing.Function: ...

    def getVariables(self, __a0: ghidra.program.model.listing.VariableFilter) -> List[ghidra.program.model.listing.Variable]: ...

    def hasCustomVariableStorage(self) -> bool: ...

    def hasNoReturn(self) -> bool: ...

    def hasUnknownCallingConventionName(self) -> bool: ...

    def hasVarArgs(self) -> bool: ...

    def hashCode(self) -> int: ...

    def insertParameter(self, __a0: int, __a1: ghidra.program.model.listing.Variable, __a2: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Parameter: ...

    def isDeleted(self) -> bool: ...

    def isExternal(self) -> bool: ...

    def isGlobal(self) -> bool: ...

    def isInline(self) -> bool: ...

    def isLibrary(self) -> bool: ...

    def isStackPurgeSizeValid(self) -> bool: ...

    def isThunk(self) -> bool: ...

    def moveParameter(self, __a0: int, __a1: int) -> ghidra.program.model.listing.Parameter: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def promoteLocalUserLabelsToGlobal(self) -> None: ...

    def removeParameter(self, __a0: int) -> None: ...

    def removeTag(self, __a0: unicode) -> None: ...

    def removeVariable(self, __a0: ghidra.program.model.listing.Variable) -> None: ...

    @overload
    def replaceParameters(self, __a0: List[object], __a1: ghidra.program.model.listing.Function.FunctionUpdateType, __a2: bool, __a3: ghidra.program.model.symbol.SourceType) -> None: ...

    @overload
    def replaceParameters(self, __a0: ghidra.program.model.listing.Function.FunctionUpdateType, __a1: bool, __a2: ghidra.program.model.symbol.SourceType, __a3: List[ghidra.program.model.listing.Variable]) -> None: ...

    def setBody(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    def setCallFixup(self, __a0: unicode) -> None: ...

    def setCallingConvention(self, __a0: unicode) -> None: ...

    def setComment(self, __a0: unicode) -> None: ...

    def setCustomVariableStorage(self, __a0: bool) -> None: ...

    def setDestinationFunction(self, function: ghidra.program.model.listing.Function) -> None:
        """
        Set the destination function which corresponds to this thunk.
        @param function destination function
        """
        ...

    def setInline(self, __a0: bool) -> None: ...

    def setName(self, __a0: unicode, __a1: ghidra.program.model.symbol.SourceType) -> None: ...

    def setNoReturn(self, __a0: bool) -> None: ...

    def setParentNamespace(self, __a0: ghidra.program.model.symbol.Namespace) -> None: ...

    def setRepeatableComment(self, __a0: unicode) -> None: ...

    def setReturn(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.listing.VariableStorage, __a2: ghidra.program.model.symbol.SourceType) -> None: ...

    def setReturnType(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.symbol.SourceType) -> None: ...

    def setSignatureSource(self, __a0: ghidra.program.model.symbol.SourceType) -> None: ...

    def setStackPurgeSize(self, __a0: int) -> None: ...

    def setThunkedFunction(self, __a0: ghidra.program.model.listing.Function) -> None: ...

    def setVarArgs(self, __a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def updateFunction(self, __a0: unicode, __a1: ghidra.program.model.listing.Variable, __a2: List[object], __a3: ghidra.program.model.listing.Function.FunctionUpdateType, __a4: bool, __a5: ghidra.program.model.symbol.SourceType) -> None: ...

    @overload
    def updateFunction(self, __a0: unicode, __a1: ghidra.program.model.listing.Variable, __a2: ghidra.program.model.listing.Function.FunctionUpdateType, __a3: bool, __a4: ghidra.program.model.symbol.SourceType, __a5: List[ghidra.program.model.listing.Variable]) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def ID(self) -> long: ...

    @property
    def allVariables(self) -> List[ghidra.program.model.listing.Variable]: ...

    @property
    def autoParameterCount(self) -> int: ...

    @property
    def body(self) -> ghidra.program.model.address.AddressSetView: ...

    @body.setter
    def body(self, value: ghidra.program.model.address.AddressSetView) -> None: ...

    @property
    def callFixup(self) -> unicode: ...

    @callFixup.setter
    def callFixup(self, value: unicode) -> None: ...

    @property
    def callingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def callingConventionName(self) -> unicode: ...

    @property
    def comment(self) -> unicode: ...

    @comment.setter
    def comment(self, value: unicode) -> None: ...

    @property
    def commentAsArray(self) -> List[unicode]: ...

    @property
    def customVariableStorage(self) -> None: ...  # No getter available.

    @customVariableStorage.setter
    def customVariableStorage(self, value: bool) -> None: ...

    @property
    def deleted(self) -> bool: ...

    @property
    def destinationFunction(self) -> None: ...  # No getter available.

    @destinationFunction.setter
    def destinationFunction(self, value: ghidra.program.model.listing.Function) -> None: ...

    @property
    def destinationFunctionEntryPoint(self) -> ghidra.program.model.address.Address: ...

    @property
    def entryPoint(self) -> ghidra.program.model.address.Address: ...

    @property
    def external(self) -> bool: ...

    @property
    def externalLocation(self) -> ghidra.program.model.symbol.ExternalLocation: ...

    @property
    def functionThunkAddresses(self) -> List[ghidra.program.model.address.Address]: ...

    @property
    def global(self) -> bool: ...

    @property
    def inline(self) -> bool: ...

    @inline.setter
    def inline(self, value: bool) -> None: ...

    @property
    def library(self) -> bool: ...

    @property
    def localVariables(self) -> List[ghidra.program.model.listing.Variable]: ...

    @property
    def name(self) -> unicode: ...

    @property
    def noReturn(self) -> None: ...  # No getter available.

    @noReturn.setter
    def noReturn(self, value: bool) -> None: ...

    @property
    def parameterCount(self) -> int: ...

    @property
    def parameters(self) -> List[ghidra.program.model.listing.Parameter]: ...

    @property
    def parentNamespace(self) -> ghidra.program.model.symbol.Namespace: ...

    @parentNamespace.setter
    def parentNamespace(self, value: ghidra.program.model.symbol.Namespace) -> None: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def repeatableComment(self) -> unicode: ...

    @repeatableComment.setter
    def repeatableComment(self, value: unicode) -> None: ...

    @property
    def repeatableCommentAsArray(self) -> List[unicode]: ...

    @property
    def return(self) -> ghidra.program.model.listing.Parameter: ...

    @property
    def returnType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def signature(self) -> ghidra.program.model.listing.FunctionSignature: ...

    @property
    def signatureSource(self) -> ghidra.program.model.symbol.SourceType: ...

    @signatureSource.setter
    def signatureSource(self, value: ghidra.program.model.symbol.SourceType) -> None: ...

    @property
    def stackFrame(self) -> ghidra.program.model.listing.StackFrame: ...

    @property
    def stackPurgeSize(self) -> int: ...

    @stackPurgeSize.setter
    def stackPurgeSize(self, value: int) -> None: ...

    @property
    def stackPurgeSizeValid(self) -> bool: ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol: ...

    @property
    def tags(self) -> java.util.Set: ...

    @property
    def thunk(self) -> bool: ...

    @property
    def thunkedFunction(self) -> None: ...  # No getter available.

    @thunkedFunction.setter
    def thunkedFunction(self, value: ghidra.program.model.listing.Function) -> None: ...

    @property
    def varArgs(self) -> None: ...  # No getter available.

    @varArgs.setter
    def varArgs(self, value: bool) -> None: ...
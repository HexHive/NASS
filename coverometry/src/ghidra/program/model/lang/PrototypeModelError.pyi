from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.lang.ParamList
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class PrototypeModelError(ghidra.program.model.lang.PrototypeModel):
    """
    A PrototypeModel cloned from another, but marked as an error placeholder
    """





    def __init__(self, name: unicode, copyModel: ghidra.program.model.lang.PrototypeModel): ...



    def encode(self, encoder: ghidra.program.model.pcode.Encoder, injectLibrary: ghidra.program.model.lang.PcodeInjectLibrary) -> None:
        """
        Encode this object to an output stream
        @param encoder is the stream encoder
        @param injectLibrary is a library containing any inject payloads associated with the model
        @throws IOException for errors writing to the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAliasParent(self) -> ghidra.program.model.lang.PrototypeModel:
        """
        If this is an alias of another model, return that model.  Otherwise null is returned.
        @return the parent model or null
        """
        ...

    def getArgLocation(self, argIndex: int, params: List[ghidra.program.model.listing.Parameter], dataType: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        """
        Get the preferred parameter location for a specified index,
         which will be added/inserted within the set of existing function params.
         If existing parameters use custom storage, this method should not be used.
        @param argIndex is the index
        @param params existing set parameters to which the parameter specified by
         argIndex will be added/inserted be appended (may be null).
        @param dataType dataType associated with next parameter location or null
         for a default undefined type.
        @param program is the Program
        @return parameter location or {@link VariableStorage#UNASSIGNED_STORAGE} if
         unable to determine suitable location
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getExtrapop(self) -> int:
        """
        Returns the number of extra bytes popped from the stack when a function that uses
         this model returns to its caller. This is usually just the number of bytes used to
         store the return value, but some conventions may do additional clean up of stack parameters.
         A special value of UNKNOWN_EXTRAPOP indicates that the number of bytes is unknown.
        @return the number of extra bytes popped
        """
        ...

    def getInputListType(self) -> ghidra.program.model.lang.InputListType:
        """
        @return the allocation strategy for this model
        """
        ...

    def getKilledByCallList(self) -> List[ghidra.program.model.pcode.Varnode]:
        """
        @return list of registers definitely affected by called functions
        """
        ...

    def getLikelyTrash(self) -> List[ghidra.program.model.pcode.Varnode]:
        """
        @return list of registers whose input value is likely meaningless
        """
        ...

    def getName(self) -> unicode:
        """
        @return the formal name of the model
        """
        ...

    def getNextArgLocation(self, params: List[ghidra.program.model.listing.Parameter], dataType: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        """
        Get the preferred parameter location for a new parameter which will appended
         to the end of an existing set of params.  If existing parameters use custom
         storage, this method should not be used.
        @param params existing set parameters to which the next parameter will
         be appended. (may be null)
        @param dataType dataType associated with next parameter location or null
         for a default undefined type.
        @param program is the Program
        @return next parameter location or {@link VariableStorage#UNASSIGNED_STORAGE} if
         unable to determine suitable location
        """
        ...

    def getPotentialInputRegisterStorage(self, prog: ghidra.program.model.listing.Program) -> List[ghidra.program.model.listing.VariableStorage]:
        """
        Get a list of all input storage locations consisting of a single register
        @param prog is the current Program
        @return a VariableStorage ojbect for each register
        """
        ...

    def getReturnAddress(self) -> List[ghidra.program.model.pcode.Varnode]:
        """
        @return list of registers/memory used to store the return address
        """
        ...

    def getReturnLocation(self, dataType: ghidra.program.model.data.DataType, program: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        """
        @deprecated Get the preferred return location given the specified dataType.
         In truth, there is no one location.  The routines that use this method tend
         to want the default storage location for integer or pointer return values.
        @param dataType first parameter dataType or null for an undefined type.
        @param program is the Program
        @return return location or {@link VariableStorage#UNASSIGNED_STORAGE} if
         unable to determine suitable location
        """
        ...

    def getStackParameterAlignment(self) -> int:
        """
        Assuming the model allows open ended storage of parameters on the stack,
         return the byte alignment required for individual stack parameters.
        @return the stack alignment in bytes
        """
        ...

    def getStackParameterOffset(self) -> long:
        """
        Return the byte offset where the first input parameter on the stack is allocated.
         The value is relative to the incoming stack pointer of the called function.
         For normal stacks, this is the offset of the first byte in the first parameter.
         For reverse stacks, this is the offset immediately after the last byte of the parameter.
        @return the byte offset of the first param
        """
        ...

    def getStackshift(self) -> int:
        """
        @return the number of bytes on the stack used, by this model, to store the return value
        """
        ...

    def getStorageLocations(self, program: ghidra.program.model.listing.Program, dataTypes: List[ghidra.program.model.data.DataType], addAutoParams: bool) -> List[ghidra.program.model.listing.VariableStorage]:
        """
        Compute the variable storage for a given function and set of return/parameter datatypes 
         defined by an array of data types.
        @param program is the Program
        @param dataTypes return/parameter datatypes (first element is always the return datatype, 
         i.e., minimum array length is 1)
        @param addAutoParams TODO
        @return dynamic storage locations orders by ordinal where first element corresponds to
         return storage. The returned array may also include additional auto-parameter storage 
         locations.
        """
        ...

    def getUnaffectedList(self) -> List[ghidra.program.model.pcode.Varnode]:
        """
        @return list of registers unaffected by called functions
        """
        ...

    def hasInjection(self) -> bool:
        """
        Return true if this model has specific p-code injections associated with it
         (either an "uponentry" or "uponreturn" payload),
         which are used to decompile functions with this model.
        @return true if this model uses p-code injections
        """
        ...

    def hasThisPointer(self) -> bool:
        """
        @return true if this model has an implied "this" parameter for referencing class data
        """
        ...

    def hashCode(self) -> int: ...

    def isConstructor(self) -> bool:
        """
        @return true if this model is used specifically for class constructors
        """
        ...

    def isEquivalent(self, obj: ghidra.program.model.lang.PrototypeModel) -> bool:
        """
        Determine if this PrototypeModel is equivalent to another instance
        @param obj is the other instance
        @return true if they are equivalent
        """
        ...

    def isErrorPlaceholder(self) -> bool: ...

    def isMerged(self) -> bool:
        """
        If this returns true, it indicates this model is an artificial merge of other models.
         A merged model can be used as part of the analysis process when attempting to distinguish
         between different possible models for an unknown function.
        @return true if this model is an artificial merge of other models
        """
        ...

    def isProgramExtension(self) -> bool:
        """
        @return true if this model is a Program specific extension to the CompilerSpec
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def possibleInputParamWithSlot(self, loc: ghidra.program.model.address.Address, size: int, res: ghidra.program.model.lang.ParamList.WithSlotRec) -> bool:
        """
        Determine if the given address range is possible input parameter storage for this model.
         If it is, "true" is returned, and additional information about the parameter's
         position is passed back in the provided record.
        @param loc is the starting address of the range
        @param size is the size of the range in bytes
        @param res is the pass-back record
        @return true if the range is a possible parameter
        """
        ...

    def possibleOutputParamWithSlot(self, loc: ghidra.program.model.address.Address, size: int, res: ghidra.program.model.lang.ParamList.WithSlotRec) -> bool:
        """
        Determine if the given address range is possible return value storage for this model.
         If it is, "true" is returned, and additional information about the storage
         position is passed back in the provided record.
        @param loc is the starting address of the range
        @param size is the size of the range in bytes
        @param res is the pass-back record
        @return true if the range is possible return value storage
        """
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, cspec: ghidra.program.model.lang.CompilerSpec) -> None:
        """
        Restore the model from an XML stream.
        @param parser is the XML parser (initialized to the start of the stream)
        @param cspec is the parent compiler specification owning the model
        @throws XmlParseException is there are problems parsing the XML
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
    def errorPlaceholder(self) -> bool: ...
from typing import List
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang


class VariableUtilities(object):





    class VariableConflictHandler(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def resolveConflicts(self, __a0: List[object]) -> bool: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    @overload
    @staticmethod
    def checkDataType(dataType: ghidra.program.model.data.DataType, voidOK: bool, dtMgr: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Check the specified datatype for use as a return, parameter or variable type.  It may
         not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
         <ul>
         <li>Function definition datatype</li>
         <li>An unsized/zero-element array</li>
         </ul>
        @param dataType datatype to be checked.  If null is specified the DEFAULT datatype will be
         returned.
        @param voidOK true if checking return datatype and void is allow, else false.
        @param dtMgr target datatype manager (null permitted which will adopt default data organization)
        @return cloned/mutated datatype suitable for function parameters and variables (including function return data type).
        @throws InvalidInputException if an unacceptable datatype was specified
        """
        ...

    @overload
    @staticmethod
    def checkDataType(dataType: ghidra.program.model.data.DataType, voidOK: bool, defaultSize: int, dtMgr: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Check the specified datatype for use as a return, parameter or variable type.  It may
         not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
         <ul>
         <li>Function definition datatype</li>
         <li>An unsized/zero-element array</li>
         </ul>
        @param dataType datatype to be checked
        @param voidOK true if checking return datatype and void is allow, else false.
        @param defaultSize Undefined datatype size to be used if specified datatype is null.  A value less than 1
         will result in the DEFAULT data type being returned (i.e., "undefined").
        @param dtMgr target datatype manager (null permitted which will adopt default data organization)
        @return cloned/mutated datatype suitable for function parameters and variables (including function return data type).
        @throws InvalidInputException if an unacceptable datatype was specified
        """
        ...

    @overload
    @staticmethod
    def checkDataType(dataType: ghidra.program.model.data.DataType, voidOK: bool, defaultSize: int, program: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType:
        """
        Check the specified datatype for use as a return, parameter or variable type.  It may
         not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
         <ul>
         <li>Function definition datatype</li>
         <li>An unsized/zero-element array</li>
         </ul>
        @param dataType datatype to be checked
        @param voidOK true if checking return datatype and void is allow, else false.
        @param defaultSize Undefined datatype size to be used if specified datatype is null.  A value less than 1
         will result in the DEFAULT data type being returned (i.e., "undefined").
        @param program target program
        @return cloned/mutated datatype suitable for function parameters and variables (including function return data type).
        @throws InvalidInputException if an unacceptable datatype was specified
        """
        ...

    @overload
    @staticmethod
    def checkStorage(storage: ghidra.program.model.listing.VariableStorage, dataType: ghidra.program.model.data.DataType, allowSizeMismatch: bool) -> None:
        """
        Perform variable storage checks using the specified datatype.
        @param storage variable storage whose size must match the specified data type size
        @param dataType a datatype checked using {@link #checkDataType(DataType, boolean, int, Program)}
        @param allowSizeMismatch if true size mismatch will be ignore
        @throws InvalidInputException if specified storage is not suitable for datatype
        """
        ...

    @overload
    @staticmethod
    def checkStorage(function: ghidra.program.model.listing.Function, storage: ghidra.program.model.listing.VariableStorage, dataType: ghidra.program.model.data.DataType, allowSizeMismatch: bool) -> ghidra.program.model.listing.VariableStorage:
        """
        Perform variable storage checks using the specified datatype.
        @param function if specified and variable storage size does not match the data-type size
         an attempt will be made to resize the specified storage.
        @param storage variable storage
        @param dataType a datatype checked using {@link #checkDataType(DataType, boolean, int, Program)}
        @param allowSizeMismatch if true size mismatch will be ignore
        @return original storage or resized storage with the correct size.
        @throws InvalidInputException if specified storage is not suitable for datatype
        """
        ...

    @overload
    @staticmethod
    def checkVariableConflict(function: ghidra.program.model.listing.Function, var: ghidra.program.model.listing.Variable, newStorage: ghidra.program.model.listing.VariableStorage, deleteConflictingVariables: bool) -> None:
        """
        Check for variable storage conflict and optionally remove conflicting variables.
        @param function function which corresponds to specified variable
        @param var existing function variable or null for new variable
        @param newStorage new/updated variable storage
        @param deleteConflictingVariables if true function's conflicting variables may be deleted
        @throws VariableSizeException if deleteConflictingVariables is false and another variable conflicts
        """
        ...

    @overload
    @staticmethod
    def checkVariableConflict(__a0: List[object], __a1: ghidra.program.model.listing.Variable, __a2: ghidra.program.model.listing.VariableStorage, __a3: ghidra.program.model.listing.VariableUtilities.VariableConflictHandler) -> None: ...

    @staticmethod
    def compare(v1: ghidra.program.model.listing.Variable, v2: ghidra.program.model.listing.Variable) -> int:
        """
        Compare two variables without using the instance specific compareTo method.
        @param v1 a function variable
        @param v2 another function variable
        @return a negative value if v1 &lt; v2, 0 if equal, and
         positive if v1 &gt; v2
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def equivalentVariableArrays(vars1: List[ghidra.program.model.listing.Variable], vars2: List[ghidra.program.model.listing.Variable]) -> bool: ...

    @staticmethod
    def equivalentVariables(var1: ghidra.program.model.listing.Variable, var2: ghidra.program.model.listing.Variable) -> bool: ...

    @overload
    @staticmethod
    def findExistingClassStruct(func: ghidra.program.model.listing.Function) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified function's class namespace
         within the function's program.
 
         The preferred structure will utilize a namespace-based category path, however,
         the match criteria can be fuzzy and relies primarily on the class name.
         A properly named class structure must reside within a category whose trailing 
         path either matches the class namespace or the class-parent's namespace.  
         Preference is given to it residing within the class-parent's namespace.
        @param func the function.
        @return existing structure whose name matches the specified function's class namespace
         or null if not found.
        """
        ...

    @overload
    @staticmethod
    def findExistingClassStruct(classNamespace: ghidra.program.model.listing.GhidraClass, dataTypeManager: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified class namespace
         within the specified data type manager.
 
         The preferred structure will utilize a namespace-based category path, however,
         the match criteria can be fuzzy and relies primarily on the class name.
         A properly named class structure must reside within a category whose trailing 
         path either matches the class namespace or the class-parent's namespace.  
         Preference is given to it residing within the class-parent's namespace.
        @param classNamespace class namespace
        @param dataTypeManager data type manager which should be searched.
        @return existing structure whose name matches the specified class namespace
         or null if not found.
        """
        ...

    @overload
    @staticmethod
    def findOrCreateClassStruct(function: ghidra.program.model.listing.Function) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified function's class namespace
         within the function's program.
 
         The preferred structure will utilize a namespace-based category path, however,
         the match criteria can be fuzzy and relies primarily on the class name.
         A properly named class structure must reside within a category whose trailing 
         path either matches the class namespace or the class-parent's namespace.  
         Preference is given to it residing within the class-parent's namespace.
 
         If a match is not found an empty placeholder structure will be instantiated
         and returned.  A newly instantiated structure will not be added to the data type manager
         and may refer to a non-existing category path which corresponds to the class-parent's 
         namespace.
 
         If the function is not part of a class, or if an unrelated data-type already exists with
         the class's name and category, null is returned.
        @param function function's whose class namespace is the basis for the structure
        @return new or existing structure whose name matches the function's class namespace or
         null if function not contained within a class namespace.
        """
        ...

    @overload
    @staticmethod
    def findOrCreateClassStruct(classNamespace: ghidra.program.model.listing.GhidraClass, dataTypeManager: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.Structure:
        """
        Find the structure data type which corresponds to the specified class namespace
         within the specified data type manager.
 
         The preferred structure will utilize a namespace-based category path, however,
         the match criteria can be fuzzy and relies primarily on the class name.
         A properly named class structure must reside within a category whose trailing 
         path either matches the class namespace or the class-parent's namespace.  
         Preference is given to it residing within the class-parent's namespace.
 
         If a match is not found an empty placeholder structure will be instantiated
         and returned.  A newly instantiated structure will not be added to the data type manager
         and may refer to a non-existing category path which corresponds to the class-parent's 
         namespace.
 
         If an unrelated data-type already exists matching the class name and category,
         null is returned.
        @param classNamespace class namespace
        @param dataTypeManager data type manager which should be searched and whose
         data organization should be used.
        @return new or existing structure whose name matches the specified class namespace
        """
        ...

    @staticmethod
    def getAutoDataType(function: ghidra.program.model.listing.Function, returnDataType: ghidra.program.model.data.DataType, storage: ghidra.program.model.listing.VariableStorage) -> ghidra.program.model.data.DataType:
        """
        Determine the appropriate data type for an automatic parameter
        @param function function whose auto param datatype is to be determined
        @param returnDataType function's return datatype
        @param storage variable storage for an auto-parameter (isAutoStorage should be true)
        @return auto-parameter data type
        """
        ...

    @staticmethod
    def getBaseStackParamOffset(function: ghidra.program.model.listing.Function) -> int:
        """
        Determine the minimum stack offset for parameters
        @param function function whose stack use is to be examined
        @return stack parameter offset or null if it could not be determined
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getPrecedence(var: ghidra.program.model.listing.Variable) -> int:
        """
        Get a precedence value for the specified variable.
         This value can be used to assist with LocalVariable.compareTo(Variable var)
        @param var function variable
        @return numeric precedence
        """
        ...

    @staticmethod
    def getThisParameter(function: ghidra.program.model.listing.Function, convention: ghidra.program.model.lang.PrototypeModel) -> ghidra.program.model.listing.ParameterImpl:
        """
        Generate a suitable 'this' parameter for the specified function
        @param function function for which a <code>this</code> parameter is to be generated
        @param convention function calling convention
        @return this parameter or null of calling convention is not a 'thiscall'
         or some other error prevents it
        @deprecated should rely on auto-param instead - try not to use this method which may be eliminated
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def resizeStorage(curStorage: ghidra.program.model.listing.VariableStorage, dataType: ghidra.program.model.data.DataType, alignStack: bool, function: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.VariableStorage:
        """
        Perform resize variable storage to desired newSize.  This method has limited ability to grow
         storage if current storage does not have a stack component or if other space constraints
         are exceeded.
        @param curStorage current variable storage
        @param dataType variable datatype
        @param alignStack if false no attempt is made to align stack usage for big-endian
        @param function function which corresponds to resized variable storage
        @return resize storage
        @throws InvalidInputException if unable to resize storage to specified size.
        """
        ...

    @overload
    @staticmethod
    def storageMatches(__a0: List[object], __a1: List[ghidra.program.model.listing.Variable]) -> bool: ...

    @overload
    @staticmethod
    def storageMatches(__a0: List[object], __a1: List[object]) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


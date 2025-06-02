import ghidra.app.context
import ghidra.program.model.data
import java.lang


class DataService(object):
    """
    Service for creating data
    """









    def createData(self, dt: ghidra.program.model.data.DataType, context: ghidra.app.context.ListingActionContext, stackPointers: bool, enableConflictHandling: bool) -> bool:
        """
        Apply the given data type at a location.
        @param dt data type to create at the location
        @param context the context containing program, location, and selection information
        @param stackPointers if true, and supported, and the existing context-specified data is a 
         pointer, the specified datatype should be stacked onto the existing pointer if permitted.
         (see {@link DataUtilities#reconcileAppliedDataType(DataType, DataType, boolean)}).
        @param enableConflictHandling if true, the service may prompt the user to resolve data 
                conflicts
        @return true if the data could be created at the current location
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isCreateDataAllowed(self, context: ghidra.app.context.ListingActionContext) -> bool:
        """
        Determine if create data is permitted on the specified location. If the
         location is contained within the current program selection, the entire
         selection is examined.
        @param context the context containing program, location, and selection information
        @return true if create data is allowed, else false.
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


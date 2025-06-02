import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.util.task
import java.lang


class ApplyFunctionDataTypesCmd(ghidra.framework.cmd.BackgroundCommand):
    """
    Apply all function signature data types in a data type manager to
     any user defined label that has the same name as the function
     signature.
    """





    @overload
    def __init__(self, sourceCategory: ghidra.program.model.data.Category, set: ghidra.program.model.address.AddressSetView, source: ghidra.program.model.symbol.SourceType, alwaysReplace: bool, createBookmarksEnabled: bool):
        """
        Constructs a new command to apply all function signature data types
         in the given data type category (includes all subcategories).
        @param sourceCategory datatype category containing the function signature data types
        @param set set of addresses containing labels to match against function names.
         			  The addresses must not already be included in the body of any existing function.
          		  If null, all symbols will be processed
        @param source the source of this command.
        @param alwaysReplace true to always replace the existing function signature with the
         						function signature data type.
        @param createBookmarksEnabled true to create a bookmark when a function signature
         								 has been applied.
        """
        ...

    @overload
    def __init__(self, __a0: List[object], __a1: ghidra.program.model.address.AddressSetView, __a2: ghidra.program.model.symbol.SourceType, __a3: bool, __a4: bool): ...



    @overload
    def applyTo(self, obj: ghidra.framework.model.DomainObject) -> bool: ...

    @overload
    def applyTo(self, obj: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor) -> bool: ...

    def canCancel(self) -> bool:
        """
        Check if the command can be canceled.
        @return true if this command can be canceled
        """
        ...

    def dispose(self) -> None:
        """
        Called when this command is going to be removed/canceled without
         running it.  This gives the command the opportunity to free any
         temporary resources it has hold of.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getName(self) -> unicode: ...

    def getStatusMsg(self) -> unicode: ...

    def hasProgress(self) -> bool:
        """
        Check if the command provides progress information.
        @return true if the command shows progress information
        """
        ...

    def hashCode(self) -> int: ...

    def isModal(self) -> bool:
        """
        Check if the command requires the monitor to be modal.  No other
         command should be allowed, and the GUI will be locked.
        @return true if no other operation should be going on while this
         command is in progress.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def taskCompleted(self) -> None:
        """
        Called when the task monitor is completely done with indicating progress.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


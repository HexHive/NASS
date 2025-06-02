from typing import List
import ghidra.app.tablechooser
import ghidra.util.task
import java.lang


class TableChooserExecutor(object):
    """
    The interface clients must implement to use the TableChooserDialog.  This class is the
     callback that is used to process items from the dialog's table as users select one or more
     rows in the table and then press the table's "apply" button.
    """









    def equals(self, __a0: object) -> bool: ...

    def execute(self, rowObject: ghidra.app.tablechooser.AddressableRowObject) -> bool:
        """
        Applies this executors action to the given rowObject.  Return true if the given object
         should be removed from the table.

         <P>This method call will be wrapped in a transaction so the client does not have to do so.
         Multiple selected rows will all be processed in a single transaction.
        @param rowObject the AddressRowObject to be executed upon
        @return true if the rowObject should be removed from the table, false otherwise
        """
        ...

    def executeInBulk(self, __a0: List[object], __a1: List[object], __a2: ghidra.util.task.TaskMonitor) -> bool: ...

    def getButtonName(self) -> unicode:
        """
        A short name suitable for display in the "apply" button that indicates what the "apply"
         action does.
        @return A short name suitable for display in the "apply" button that indicates what the "apply"
         action does.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

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
    def buttonName(self) -> unicode: ...
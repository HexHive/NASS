import ghidra.util.task
import java.lang


class TaskMonitor(object):
    """
    TaskMonitor provides an interface that allows potentially long running tasks to show
     progress and check for user has cancellation.
 
     Tasks that support a task monitor should periodically check to see if the operation has been
     cancelled and abort. If possible, the task should also provide periodic progress information. If
     your task can estimate the amount of work done, then it should use the #setProgress(long)
     method, otherwise it should call #setMessage(String) method to provide status updates.
    """

    DUMMY: ghidra.util.task.TaskMonitor = ghidra.util.task.StubTaskMonitor@3a85dbea
    NO_PROGRESS_VALUE: int = -1







    def addCancelledListener(self, listener: ghidra.util.task.CancelledListener) -> None:
        """
        Add cancelled listener
        @param listener the cancel listener
        """
        ...

    def cancel(self) -> None:
        """
        Cancel the task
        """
        ...

    def checkCanceled(self) -> None:
        """
        Check to see if this monitor has been cancelled
        @throws CancelledException if monitor has been cancelled
        @deprecated Use {@link #checkCancelled()} instead
        """
        ...

    def checkCancelled(self) -> None:
        """
        Check to see if this monitor has been cancelled
        @throws CancelledException if monitor has been cancelled
        """
        ...

    def clearCanceled(self) -> None:
        """
        Clear the cancellation so that this TaskMonitor may be reused
        @deprecated Use {@link #clearCancelled()} instead
        """
        ...

    def clearCancelled(self) -> None:
        """
        Clear the cancellation so that this TaskMonitor may be reused
        """
        ...

    @staticmethod
    def dummyIfNull(tm: ghidra.util.task.TaskMonitor) -> ghidra.util.task.TaskMonitor:
        """
        Returns the given task monitor if it is not {@code null}.  Otherwise, a {@link #DUMMY}
         monitor is returned.
        @param tm the monitor to check for {@code null}
        @return a non-null task monitor
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMaximum(self) -> long:
        """
        Returns the current maximum value for progress
        @return the maximum progress value
        """
        ...

    def getMessage(self) -> unicode:
        """
        Gets the last set message of this monitor
        @return the message
        """
        ...

    def getProgress(self) -> long:
        """
        Returns the current progress value or {@link #NO_PROGRESS_VALUE} if there is no value set
        @return the current progress value or {@link #NO_PROGRESS_VALUE} if there is no value set
        """
        ...

    def hashCode(self) -> int: ...

    @overload
    def increment(self) -> None:
        """
        Increases the progress value by 1, and checks if this monitor has been cancelled.
        @throws CancelledException if monitor has been cancelled
        """
        ...

    @overload
    def increment(self, incrementAmount: long) -> None:
        """
        Changes the progress value by the specified amount, and checks if this monitor has 
         been cancelled.
        @param incrementAmount The amount by which to increment the progress
        @throws CancelledException if monitor has been cancelled
        """
        ...

    @overload
    def incrementProgress(self) -> None:
        """
        Increases the progress value by 1.
        """
        ...

    @overload
    def incrementProgress(self, incrementAmount: long) -> None:
        """
        Changes the progress value by the specified amount.
        @param incrementAmount The amount by which to increment the progress
        """
        ...

    @overload
    def initialize(self, max: long) -> None:
        """
        Initialized this TaskMonitor to the given max values.  The current value of this monitor
         will be set to zero.
        @param max maximum value for progress
        """
        ...

    @overload
    def initialize(self, max: long, message: unicode) -> None:
        """
        Initializes the progress value to 0, sets the max value and message of this monitor.
        @param max maximum value for progress
        @param message the message to display
        """
        ...

    def isCancelEnabled(self) -> bool:
        """
        Returns true if cancel ability is enabled
        @return true if cancel ability is enabled
        """
        ...

    def isCancelled(self) -> bool:
        """
        Returns true if the user has cancelled the operation
        @return true if the user has cancelled the operation
        """
        ...

    def isIndeterminate(self) -> bool:
        """
        Returns true if this monitor shows no progress
        @return true if this monitor shows no progress
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeCancelledListener(self, listener: ghidra.util.task.CancelledListener) -> None:
        """
        Remove cancelled listener
        @param listener the cancel listener
        """
        ...

    def setCancelEnabled(self, enable: bool) -> None:
        """
        Set the enablement of the Cancel button
        @param enable true means to enable the cancel button
        """
        ...

    def setIndeterminate(self, indeterminate: bool) -> None:
        """
        An indeterminate task monitor may choose to show an animation instead of updating progress
        @param indeterminate true if indeterminate
        """
        ...

    def setMaximum(self, max: long) -> None:
        """
        Set the progress maximum value
         <p><b>
         Note: setting this value will reset the progress to be the max if the progress is currently
         greater than the new new max value.</b>
        @param max maximum value for progress
        """
        ...

    def setMessage(self, message: unicode) -> None:
        """
        Sets the message displayed on the task monitor
        @param message the message to display
        """
        ...

    def setProgress(self, value: long) -> None:
        """
        Sets the current progress value
        @param value progress value
        """
        ...

    def setShowProgressValue(self, showProgressValue: bool) -> None:
        """
        True (the default) signals to paint the progress information inside of the progress bar
        @param showProgressValue true to paint the progress value; false to not
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
    def cancelEnabled(self) -> bool: ...

    @cancelEnabled.setter
    def cancelEnabled(self, value: bool) -> None: ...

    @property
    def cancelled(self) -> bool: ...

    @property
    def indeterminate(self) -> bool: ...

    @indeterminate.setter
    def indeterminate(self, value: bool) -> None: ...

    @property
    def maximum(self) -> long: ...

    @maximum.setter
    def maximum(self, value: long) -> None: ...

    @property
    def message(self) -> unicode: ...

    @message.setter
    def message(self, value: unicode) -> None: ...

    @property
    def progress(self) -> long: ...

    @progress.setter
    def progress(self, value: long) -> None: ...

    @property
    def showProgressValue(self) -> None: ...  # No getter available.

    @showProgressValue.setter
    def showProgressValue(self, value: bool) -> None: ...
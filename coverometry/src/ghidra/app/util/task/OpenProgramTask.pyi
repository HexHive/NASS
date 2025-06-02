from typing import List
import ghidra.app.util.task.OpenProgramTask
import ghidra.framework.model
import ghidra.program.model.listing
import ghidra.util.task
import java.lang
import java.net


class OpenProgramTask(ghidra.util.task.Task):





    class OpenProgramRequest(object):




        @overload
        def __init__(self, __a0: ghidra.app.util.task.OpenProgramTask, __a1: java.net.URL): ...

        @overload
        def __init__(self, __a0: ghidra.app.util.task.OpenProgramTask, __a1: ghidra.framework.model.DomainFile, __a2: int, __a3: bool): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDomainFile(self) -> ghidra.framework.model.DomainFile: ...

        def getGhidraURL(self) -> java.net.URL: ...

        def getLinkURL(self) -> java.net.URL: ...

        def getProgram(self) -> ghidra.program.model.listing.Program: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def release(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def domainFile(self) -> ghidra.framework.model.DomainFile: ...

        @property
        def ghidraURL(self) -> java.net.URL: ...

        @property
        def linkURL(self) -> java.net.URL: ...

        @property
        def program(self) -> ghidra.program.model.listing.Program: ...

    @overload
    def __init__(self, consumer: object): ...

    @overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile, consumer: object): ...

    @overload
    def __init__(self, ghidraURL: java.net.URL, consumer: object): ...

    @overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile, version: int, consumer: object): ...

    @overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile, forceReadOnly: bool, consumer: object): ...

    @overload
    def __init__(self, domainFile: ghidra.framework.model.DomainFile, version: int, forceReadOnly: bool, consumer: object): ...



    @overload
    def addProgramToOpen(self, ghidraURL: java.net.URL) -> None: ...

    @overload
    def addProgramToOpen(self, domainFile: ghidra.framework.model.DomainFile, version: int) -> None: ...

    @overload
    def addProgramToOpen(self, domainFile: ghidra.framework.model.DomainFile, version: int, forceReadOnly: bool) -> None: ...

    def addTaskListener(self, listener: ghidra.util.task.TaskListener) -> None:
        """
        Sets the task listener on this task.  It is a programming error to call this method more
         than once or to call this method if a listener was passed into the constructor of this class.
        @param listener the listener
        """
        ...

    def canCancel(self) -> bool:
        """
        Returns true if the task can be canceled.
        @return boolean true if the user can cancel the task
        """
        ...

    def cancel(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getOpenProgram(self) -> ghidra.app.util.task.OpenProgramTask.OpenProgramRequest:
        """
        Get the first successful open program request
        @return first successful open program request or null if none
        """
        ...

    def getOpenPrograms(self) -> List[ghidra.app.util.task.OpenProgramTask.OpenProgramRequest]:
        """
        Get all successful open program requests
        @return all successful open program requests
        """
        ...

    def getStatusTextAlignment(self) -> int:
        """
        Returns the alignment of the text displayed in the modal dialog.  The default is
         {@link SwingConstants#CENTER}.   For status updates where the initial portion of the
         text does not change, {@link SwingConstants#LEADING} is recommended.  To change the
         default value, simply override this method and return one of {@link SwingConstants}
         CENTER, LEADING or TRAILING.
        @return the alignment of the text displayed
        """
        ...

    def getTaskTitle(self) -> unicode:
        """
        Get the title associated with the task
        @return String title shown in the dialog
        """
        ...

    def getWaitForTaskCompleted(self) -> bool:
        """
        Returns the value of the 'wait for completed task' boolean that was passed into this class
        @return the value
        """
        ...

    def hasOpenProgramRequests(self) -> bool: ...

    def hasProgress(self) -> bool:
        """
        Return true if the task has a progress indicator.
        @return boolean true if the task shows progress
        """
        ...

    def hashCode(self) -> int: ...

    def isCancelled(self) -> bool: ...

    def isModal(self) -> bool:
        """
        Returns true if the dialog associated with the task is modal.
        @return boolean true if the associated dialog is modal
        """
        ...

    def monitoredRun(self, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        When an object implementing interface <code>Runnable</code> is used to create a thread,
         starting the thread causes the object's <code>run</code> method to be called in that
         separately executing thread.
        @param monitor the task monitor
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def run(self, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def setHasProgress(self, b: bool) -> None:
        """
        Sets this task to have progress or not.  Note: changing this value after launching the
         task will have no effect.
        @param b true to show progress, false otherwise.
        """
        ...

    def setNoCheckout(self) -> None:
        """
        Invoking this method prior to task execution will prevent
         the use of optional checkout which require prompting the
         user.
        """
        ...

    def setOpenPromptText(self, text: unicode) -> None: ...

    def setSilent(self) -> None:
        """
        Invoking this method prior to task execution will prevent
         any confirmation interaction with the user (e.g., 
         optional checkout, snapshot recovery, etc.).  Errors
         may still be displayed if they occur.
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
    def openProgram(self) -> ghidra.app.util.task.OpenProgramTask.OpenProgramRequest: ...

    @property
    def openPrograms(self) -> List[object]: ...

    @property
    def openPromptText(self) -> None: ...  # No getter available.

    @openPromptText.setter
    def openPromptText(self, value: unicode) -> None: ...
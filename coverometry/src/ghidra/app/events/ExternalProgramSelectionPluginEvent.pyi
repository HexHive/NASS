import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import java.lang


class ExternalProgramSelectionPluginEvent(ghidra.framework.plugintool.PluginEvent):
    """
    Plugin event generated when a tool receives an
     ProgramSelectionToolEvent; the selection in the external tool has
     changed.
    """

    NAME: unicode = u'ExternalProgramSelection'
    TOOL_EVENT_NAME: unicode = u'Program Selection'



    def __init__(self, src: unicode, sel: ghidra.program.util.ProgramSelection, program: ghidra.program.model.listing.Program):
        """
        Construct a new event.
        @param src source of this event
        @param sel selection
        @param program program that is open
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEventName(self) -> unicode:
        """
        Get the plugin event name.
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the Program object that the selection refers to.
        """
        ...

    def getSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        Get the selection for this event.
        """
        ...

    def getSourceName(self) -> unicode:
        """
        Returns the name of the plugin immediately responsible for firing this
         event.
        """
        ...

    def getToolEventName(self) -> unicode:
        """
        Get the optional cross-tool event name which has been established via
         a {@link ToolEventName} annotation which makes it available for
         passing as an external tool via a {@link ToolConnection}.
         This name may differ from the {@link #getEventName()}.s
        @return tool event name or null if not permitted as a cross-tool event
        """
        ...

    def getTriggerEvent(self) -> ghidra.framework.plugintool.PluginEvent: ...

    def hashCode(self) -> int: ...

    def isToolEvent(self) -> bool:
        """
        Determine if this event has been annotated with a {@link ToolEventName} which
         makes it available for passing to another tool via a {@link ToolConnection}.
        @return true if event can be utilized as a cross-tool event
        """
        ...

    @staticmethod
    def lookupToolEventName(pluginEventClass: java.lang.Class) -> unicode:
        """
        Returns the tool event name corresponding to the given pluginEventClass.
         If no corresponding tool event exists, null will be returned.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setSourceName(self, s: unicode) -> None: ...

    def setTriggerEvent(self, triggerEvent: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def selection(self) -> ghidra.program.util.ProgramSelection: ...
from typing import List
import ghidra.app.plugin.core.debug.gui.copying
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.trace.model.program
import ghidra.util.task
import java.lang
import java.util
import javax.swing


class DebuggerCopyPlan(object):





    class Copier(object):








        def copy(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.model.address.AddressRange, __a2: ghidra.program.model.listing.Program, __a3: ghidra.program.model.address.Address, __a4: ghidra.util.task.TaskMonitor) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getName(self) -> unicode: ...

        def getRequiredBy(self) -> java.util.Collection: ...

        def getRequires(self) -> java.util.Collection: ...

        def hashCode(self) -> int: ...

        def isAvailable(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.model.listing.Program) -> bool: ...

        def isRequiresInitializedMemory(self) -> bool: ...

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
        def name(self) -> unicode: ...

        @property
        def requiredBy(self) -> java.util.Collection: ...

        @property
        def requires(self) -> java.util.Collection: ...

        @property
        def requiresInitializedMemory(self) -> bool: ...




    class AllCopiers(java.lang.Enum, ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.Copier):
        BOOKMARKS: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = BOOKMARKS
        BREAKPOINTS: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = BREAKPOINTS
        BYTES: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = BYTES
        COMMENTS: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = COMMENTS
        DATA: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = DATA
        DYNAMIC_DATA: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = DYNAMIC_DATA
        INSTRUCTIONS: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = INSTRUCTIONS
        LABELS: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = LABELS
        REFERENCES: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = REFERENCES
        STATE: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers = STATE
        VALUES: List[object] = [BOOKMARKS, BREAKPOINTS, BYTES, COMMENTS, DATA, DYNAMIC_DATA, INSTRUCTIONS, LABELS, REFERENCES, STATE]







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def copy(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.model.address.AddressRange, __a2: ghidra.program.model.listing.Program, __a3: ghidra.program.model.address.Address, __a4: ghidra.util.task.TaskMonitor) -> None: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def getName(self) -> unicode: ...

        def getRequiredBy(self) -> java.util.Collection: ...

        def getRequires(self) -> java.util.Collection: ...

        def hashCode(self) -> int: ...

        def isAvailable(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.model.listing.Program) -> bool: ...

        def isRequiresInitializedMemory(self) -> bool: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def requiredBy(self) -> java.util.Collection: ...

        @property
        def requires(self) -> java.util.Collection: ...

        @property
        def requiresInitializedMemory(self) -> bool: ...

    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def execute(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.model.address.AddressRange, __a2: ghidra.program.model.listing.Program, __a3: ghidra.program.model.address.Address, __a4: ghidra.util.task.TaskMonitor) -> None: ...

    def getAllCopiers(self) -> java.util.Collection: ...

    def getCheckBox(self, __a0: ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.Copier) -> javax.swing.JCheckBox: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isRequiresInitializedMemory(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def selectAll(self) -> None: ...

    def selectNone(self) -> None: ...

    def syncCopiersEnabled(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.model.listing.Program) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def allCopiers(self) -> java.util.Collection: ...
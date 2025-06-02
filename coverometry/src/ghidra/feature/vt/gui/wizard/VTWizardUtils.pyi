import ghidra.framework.model
import java.awt
import java.lang


class VTWizardUtils(object):
    PROGRAM_FILTER: ghidra.framework.model.DomainFileFilter = ghidra.feature.vt.gui.wizard.VTWizardUtils$$Lambda$474/0x0000000101887858@1ff5b1a4
    VT_SESSION_FILTER: ghidra.framework.model.DomainFileFilter = ghidra.feature.vt.gui.wizard.VTWizardUtils$1@105d0c14



    def __init__(self): ...



    @staticmethod
    def askUserToSave(__a0: java.awt.Component, __a1: ghidra.framework.model.DomainFile) -> bool: ...

    @staticmethod
    def askUserToSaveBeforeClosing(__a0: java.awt.Component, __a1: ghidra.framework.model.DomainFile) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

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


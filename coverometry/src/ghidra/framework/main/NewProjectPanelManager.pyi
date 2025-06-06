import docking.wizard
import java.awt
import java.lang


class NewProjectPanelManager(object, docking.wizard.PanelManager):
    """
    Manage the panels for the "New Project" wizard. The wizard handles 
     creating a local project and a "shared" project.
     If the project is shared, the panel order is 
     (1) Server Info
     (2) Repository panel
     (3) Project access panel (if user has admin privileges AND user is 
          creating a new repository)
     (4) Specify Project Location panel.
     If the project is not shared, the only other panel to show is the
     Specify Project Location panel.
    """









    def canFinish(self) -> bool: ...

    def cancel(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def finish(self) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getInitialPanel(self) -> docking.wizard.WizardPanel: ...

    def getNextPanel(self) -> docking.wizard.WizardPanel: ...

    def getPanelSize(self) -> java.awt.Dimension: ...

    def getPreviousPanel(self) -> docking.wizard.WizardPanel: ...

    def getStatusMessage(self) -> unicode: ...

    def getWizardManager(self) -> docking.wizard.WizardManager: ...

    def hasNextPanel(self) -> bool: ...

    def hasPreviousPanel(self) -> bool: ...

    def hashCode(self) -> int: ...

    def initialize(self) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setWizardManager(self, wm: docking.wizard.WizardManager) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


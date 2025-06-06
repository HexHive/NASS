from typing import List
import docking.framework
import ghidra.util
import java.awt
import java.lang
import javax.swing


class GhidraApplicationInformationDisplayFactory(docking.framework.ApplicationInformationDisplayFactory):




    def __init__(self): ...



    @staticmethod
    def createAboutComponent() -> javax.swing.JComponent: ...

    @staticmethod
    def createAboutTitle() -> unicode: ...

    @staticmethod
    def createHelpLocation() -> ghidra.util.HelpLocation: ...

    @staticmethod
    def createSplashScreenComponent() -> javax.swing.JComponent: ...

    @staticmethod
    def createSplashScreenTitle() -> unicode: ...

    def doGetHomeIcon(self) -> javax.swing.Icon: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getHomeCallback() -> java.lang.Runnable: ...

    @staticmethod
    def getHomeIcon() -> javax.swing.Icon: ...

    @staticmethod
    def getLargestWindowIcon() -> java.awt.Image: ...

    @staticmethod
    def getWindowIcons() -> List[java.awt.Image]: ...

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


import docking.help
import ghidra.util
import ghidra.util.task
import help
import java.awt
import java.lang
import java.net
import java.util


class GhidraHelpService(docking.help.HelpManager):
    """
    Ghidra's help service.   This class knows how to find help for the various modules that 
     make up Ghidra.
    """









    def addHelpSet(self, url: java.net.URL, classLoader: docking.help.GHelpClassLoader) -> None:
        """
        Add the help set for the given URL.
        @param url url for the HelpSet (.hs) file
        @param classLoader the help classloader that knows how to find help modules in the classpath
        @throws HelpSetException if the help set could not be created from the given URL.
        """
        ...

    def clearHelp(self, helpObject: object) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def excludeFromHelp(self, helpObject: object) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getHelpLocation(self, helpObj: object) -> ghidra.util.HelpLocation: ...

    def getInvalidHelpLocations(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.Map: ...

    def getMasterHelpSet(self) -> help.GHelpSet:
        """
        Returns the master help set (the one into which all other help sets are merged).
        @return the help set
        """
        ...

    def hashCode(self) -> int: ...

    def helpExists(self) -> bool: ...

    @staticmethod
    def install() -> None: ...

    def isExcludedFromHelp(self, helpObject: object) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def registerHelp(self, helpObject: object, location: ghidra.util.HelpLocation) -> None: ...

    def reload(self) -> None: ...

    @overload
    def showHelp(self, loc: ghidra.util.HelpLocation) -> None: ...

    @overload
    def showHelp(self, url: java.net.URL) -> None: ...

    @overload
    def showHelp(self, helpObj: object, infoOnly: bool, owner: java.awt.Component) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


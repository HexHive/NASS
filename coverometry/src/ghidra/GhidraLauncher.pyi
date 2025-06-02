from typing import List
import generic.jar
import ghidra
import java.lang


class GhidraLauncher(object):
    """
    Class used to prepare Ghidra for launching
 
     A #main(String[]) method is provided which redirects execution to a 
     GhidraLaunchable class passed in as a command line argument
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findJarsInDir(dir: generic.jar.ResourceFile) -> List[unicode]:
        """
        Searches the given directory (non-recursively) for jars and returns their paths in a list.
         The paths will be sorted by jar file name.
        @param dir The directory to search for jars in
        @return A list of discovered jar paths, sorted by jar file name
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def initializeGhidraEnvironment() -> ghidra.GhidraApplicationLayout:
        """
        Initializes the Ghidra environment by discovering its {@link GhidraApplicationLayout layout}
         and adding all relevant modules and libraries to the classpath
         <p>
         NOTE: This method expects that the {@link GhidraClassLoader} is the active classloader
        @return Ghidra's {@link GhidraApplicationLayout layout}
        @throws IOException if there was an issue getting the {@link GhidraApplicationLayout layout}
        @throws ClassNotFoundException if the {@link GhidraClassLoader} is not the active classloader
        """
        ...

    @staticmethod
    def launch(args: List[unicode]) -> None:
        """
        Launches the given {@link GhidraLaunchable} specified in the first command line argument
        @param args The first argument is the name of the {@link GhidraLaunchable} to launch.
           The remaining args get passed through to the class's {@link GhidraLaunchable#launch} 
           method.
        @throws Exception If there was a problem launching.  See the exception's message for more
             details on what went wrong.
        """
        ...

    @staticmethod
    def main(args: List[unicode]) -> None:
        """
        Launches the given {@link GhidraLaunchable} specified in the first command line argument
        @param args The first argument is the name of the {@link GhidraLaunchable} to launch.
           The remaining args get passed through to the class's {@link GhidraLaunchable#launch} 
           method.
        @throws Exception If there was a problem launching.  See the exception's message for more
             details on what went wrong.
        @deprecated Use {@link Ghidra#main(String[])} instead
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


from typing import List
import java.lang


class Ghidra(object):
    """
    Ghidra entry point that forwards the command line arguments to GhidraLaunchable.
 
     This class was introduced so Ghidra's application name can be set to "ghidra-Ghidra" on Linux,
     rather than "ghidra-GhidraLauncher".
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def main(args: List[unicode]) -> None:
        """
        Launches the given {@link GhidraLaunchable} specified in the first command line argument
        @param args The first argument is the name of the {@link GhidraLaunchable} to launch.
           The remaining args get passed through to the class's {@link GhidraLaunchable#launch} 
           method.
        @throws Exception If there was a problem launching.  See the exception's message for more
             details on what went wrong.
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


import ghidra.framework.data
import java.lang


class RootGhidraFolderData(ghidra.framework.data.GhidraFolderData):








    def containsFile(self, fileName: unicode) -> bool:
        """
        Check for existence of file.  If folder previously visited, rely on fileDataCache
        @param fileName the name of the file to look for
        @return true if this folder contains the fileName, else false
        @throws IOException if an IO error occurs while checking for file existance
        """
        ...

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


import java.lang
import java.net


class RepositoryInfo(object):




    def __init__(self, repositoryURL: java.net.URL, repositoryName: unicode, readOnly: bool): ...



    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getURL(self) -> java.net.URL:
        """
        Get the Ghidra URL which corresponds to the repository
        @return repository URL
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toShortString(self) -> unicode: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def URL(self) -> java.net.URL: ...
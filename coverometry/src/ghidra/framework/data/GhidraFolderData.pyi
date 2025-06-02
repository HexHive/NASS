import java.lang


class GhidraFolderData(object):
    """
    GhidraFolderData provides the managed object which represents a project folder that 
     corresponds to matched folder paths across both a versioned and private 
     filesystem and viewed as a single folder at the project level.  This class closely mirrors the
     DomainFolder interface and is used by the GhidraFolder implementation; both of which
     represent immutable folder references.  Changes made to this folder's name or path are not reflected 
     in old DomainFolder instances and must be re-instantiated following such a change.  
     Any long-term retention of DomainFolder and DomainFile instances requires an 
     appropriate change listener to properly discard/reacquire such instances.
    """





    def __init__(self): ...



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


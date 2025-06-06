import ghidra.framework.cmd
import ghidra.framework.model
import java.lang


class CreateFunctionTagCmd(object, ghidra.framework.cmd.Command):
    """
    Command for assigning a tag to a function
    """





    @overload
    def __init__(self, name: unicode):
        """
        Constructor
        @param name the name of the new tag
        """
        ...

    @overload
    def __init__(self, name: unicode, comment: unicode):
        """
        Constructor
        @param name the name of the new tag
        @param comment the tag comment
        """
        ...



    def applyTo(self, obj: ghidra.framework.model.DomainObject) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getName(self) -> unicode: ...

    def getStatusMsg(self) -> unicode: ...

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

    @property
    def name(self) -> unicode: ...

    @property
    def statusMsg(self) -> unicode: ...
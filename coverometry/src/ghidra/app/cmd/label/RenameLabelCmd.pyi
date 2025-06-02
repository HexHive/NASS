import ghidra.framework.cmd
import ghidra.framework.model
import java.lang


class RenameLabelCmd(object, ghidra.framework.cmd.Command):
    """
    Command for renaming labels. Handles converting back and forth between default and named labels 
     as well.
    """





    @overload
    def __init__(self, symbol: ghidra.program.model.symbol.Symbol, newName: unicode, source: ghidra.program.model.symbol.SourceType):
        """
        Constructor renaming an existing symbol, but not changing its namespace
        @param symbol the existing symbol; may not be null
        @param newName the new symbol name
        @param source the desired symbol source
        """
        ...

    @overload
    def __init__(self, addr: ghidra.program.model.address.Address, oldName: unicode, newName: unicode, source: ghidra.program.model.symbol.SourceType):
        """
        Constructs a new command for renaming <B>global</B> labels.
        @param addr Address of label to be renamed
        @param oldName the name of the label to be renamed; may be null if the existing label is a 
         dynamic label
        @param newName the new name for the label
        @param source the source of this symbol
        """
        ...

    @overload
    def __init__(self, symbol: ghidra.program.model.symbol.Symbol, newName: unicode, newNamespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType):
        """
        Constructor renaming an existing symbol and changing its namespace.  If you do not need
         to change the namespace, then call {@link #RenameLabelCmd(Symbol, String, SourceType)}.
        @param symbol the existing symbol; may not be null
        @param newName the new symbol name
        @param newNamespace the new symbol namespace
        @param source the desired symbol source
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
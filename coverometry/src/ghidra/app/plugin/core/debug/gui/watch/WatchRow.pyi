from typing import List
import ghidra.docking.settings
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.symbol
import ghidra.trace.model.memory
import java.lang


class WatchRow(object):
    TRUNCATE_BYTES_LENGTH: int = 64



    def __init__(self, __a0: ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesProvider, __a1: unicode): ...



    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getError(self) -> java.lang.Throwable: ...

    def getErrorMessage(self) -> unicode: ...

    def getExpression(self) -> unicode: ...

    def getRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getRawValueString(self) -> unicode: ...

    def getReads(self) -> ghidra.program.model.address.AddressSetView: ...

    def getSettings(self) -> ghidra.docking.settings.Settings: ...

    def getState(self) -> ghidra.trace.model.memory.TraceMemoryState: ...

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    def getTypePath(self) -> unicode: ...

    def getValue(self) -> List[int]: ...

    def getValueLength(self) -> int: ...

    def getValueObj(self) -> object: ...

    def getValueString(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isChanged(self) -> bool: ...

    def isKnown(self) -> bool: ...

    def isRawValueEditable(self) -> bool: ...

    def isValueEditable(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDataType(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def setExpression(self, __a0: unicode) -> None: ...

    def setRawValueBytes(self, __a0: List[int]) -> None: ...

    def setRawValueBytesString(self, __a0: unicode) -> None: ...

    def setRawValueIntString(self, __a0: unicode) -> None: ...

    def setRawValueString(self, __a0: unicode) -> None: ...

    def setTypePath(self, __a0: unicode) -> None: ...

    def setValueString(self, __a0: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def changed(self) -> bool: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @dataType.setter
    def dataType(self, value: ghidra.program.model.data.DataType) -> None: ...

    @property
    def error(self) -> java.lang.Throwable: ...

    @property
    def errorMessage(self) -> unicode: ...

    @property
    def expression(self) -> unicode: ...

    @expression.setter
    def expression(self, value: unicode) -> None: ...

    @property
    def known(self) -> bool: ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def rawValueBytes(self) -> None: ...  # No getter available.

    @rawValueBytes.setter
    def rawValueBytes(self, value: List[int]) -> None: ...

    @property
    def rawValueBytesString(self) -> None: ...  # No getter available.

    @rawValueBytesString.setter
    def rawValueBytesString(self, value: unicode) -> None: ...

    @property
    def rawValueEditable(self) -> bool: ...

    @property
    def rawValueIntString(self) -> None: ...  # No getter available.

    @rawValueIntString.setter
    def rawValueIntString(self, value: unicode) -> None: ...

    @property
    def rawValueString(self) -> unicode: ...

    @rawValueString.setter
    def rawValueString(self, value: unicode) -> None: ...

    @property
    def reads(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def settings(self) -> ghidra.docking.settings.Settings: ...

    @property
    def state(self) -> ghidra.trace.model.memory.TraceMemoryState: ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol: ...

    @property
    def typePath(self) -> unicode: ...

    @typePath.setter
    def typePath(self, value: unicode) -> None: ...

    @property
    def value(self) -> List[int]: ...

    @property
    def valueEditable(self) -> bool: ...

    @property
    def valueLength(self) -> int: ...

    @property
    def valueObj(self) -> object: ...

    @property
    def valueString(self) -> unicode: ...

    @valueString.setter
    def valueString(self, value: unicode) -> None: ...
from typing import List
import ghidra.docking.settings
import java.lang


class DataTypeSettingsDB(object, ghidra.docking.settings.Settings):
    """
    Default Settings handler for those datatypes managed
     by an associated DataTypeManagerDB.
    """









    def clearAllSettings(self) -> None: ...

    def clearSetting(self, name: unicode) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings: ...

    def getLong(self, name: unicode) -> long: ...

    def getNames(self) -> List[unicode]: ...

    def getString(self, name: unicode) -> unicode: ...

    def getSuggestedValues(self, settingsDefinition: ghidra.docking.settings.StringSettingsDefinition) -> List[unicode]: ...

    def getValue(self, name: unicode) -> object: ...

    def hashCode(self) -> int: ...

    def isChangeAllowed(self, settingsDefinition: ghidra.docking.settings.SettingsDefinition) -> bool: ...

    def isEmpty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setLong(self, name: unicode, value: long) -> None: ...

    def setString(self, name: unicode, value: unicode) -> None: ...

    def setValue(self, name: unicode, value: object) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


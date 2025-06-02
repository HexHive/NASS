from typing import List
import ghidra.docking.settings
import java.io
import java.lang


class SettingsImpl(object, ghidra.docking.settings.Settings, java.io.Serializable):
    """
    Basic implementation of the Settings object
    """

    EMPTY_STRING_ARRAY: List[unicode] = array(java.lang.String)
    NO_SETTINGS: ghidra.docking.settings.Settings = {}



    @overload
    def __init__(self):
        """
        Construct a new SettingsImpl.
        """
        ...

    @overload
    def __init__(self, immutable: bool):
        """
        Construct a new SettingsImpl.
        @param immutable if true settings are immutable with the exception of
          setting its default settings.  If false settings may be modified.
        """
        ...

    @overload
    def __init__(self, settings: ghidra.docking.settings.Settings):
        """
        Construct a new SettingsImpl object.  If settings object is specified this
         settings will copy all name/value pairs and underlying defaults.
        @param settings the settings object to copy
        """
        ...

    @overload
    def __init__(self, allowedSettingPredicate: java.util.function.Predicate):
        """
        Construct a new SettingsImpl with a modification predicate.
        @param allowedSettingPredicate callback for checking an allowed setting modification
        """
        ...

    @overload
    def __init__(self, listener: javax.swing.event.ChangeListener, changeSourceObj: object):
        """
        Construct a new SettingsImpl with the given listener
        @param listener object to be notified as settings values change
        @param changeSourceObj source object to be associated with change events
        """
        ...



    def clearAllSettings(self) -> None: ...

    def clearSetting(self, name: unicode) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings: ...

    def getLong(self, name: unicode) -> long: ...

    def getNames(self) -> List[unicode]: ...

    def getString(self, name: unicode) -> unicode: ...

    def getSuggestedValues(self, __a0: ghidra.docking.settings.StringSettingsDefinition) -> List[unicode]: ...

    def getValue(self, name: unicode) -> object: ...

    def hashCode(self) -> int: ...

    def isChangeAllowed(self, settingsDefinition: ghidra.docking.settings.SettingsDefinition) -> bool: ...

    def isEmpty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDefaultSettings(self, settings: ghidra.docking.settings.Settings) -> None: ...

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

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings: ...

    @defaultSettings.setter
    def defaultSettings(self, value: ghidra.docking.settings.Settings) -> None: ...

    @property
    def empty(self) -> bool: ...

    @property
    def names(self) -> List[unicode]: ...
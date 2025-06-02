from typing import List
import ghidra.docking.settings
import java.lang
import java.util
import java.util.function


class StringSettingsDefinition(ghidra.docking.settings.SettingsDefinition, object):








    def addPreferredValues(self, settingsOwner: object, set: java.util.Set) -> bool:
        """
        Add preferred setting values to the specified set as obtained from the specified
         settingsOwner.
        @param settingsOwner settings owner from which a definition may query preferred values.
         Supported values are specific to this settings definition.  An unsupported settingsOwner
         will return false.
        @param set value set to which values should be added
        @return true if settingsOwner is supported and set updated, else false.
        """
        ...

    def clear(self, __a0: ghidra.docking.settings.Settings) -> None: ...

    @staticmethod
    def concat(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: List[ghidra.docking.settings.SettingsDefinition]) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def copySetting(self, __a0: ghidra.docking.settings.Settings, __a1: ghidra.docking.settings.Settings) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def filterSettingsDefinitions(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: java.util.function.Predicate) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def getStorageKey(self) -> unicode: ...

    def getSuggestedValues(self, settings: ghidra.docking.settings.Settings) -> List[unicode]:
        """
        Get suggested setting values
        @param settings settings object
        @return suggested settings or null if none or unsupported;
        """
        ...

    def getValue(self, settings: ghidra.docking.settings.Settings) -> unicode:
        """
        Gets the value for this SettingsDefinition given a Settings object.
        @param settings the set of Settings values for a particular location or null for default value.
        @return the value for this settings object given the context.
        """
        ...

    def getValueString(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    def hasSameValue(self, settings1: ghidra.docking.settings.Settings, settings2: ghidra.docking.settings.Settings) -> bool: ...

    def hasValue(self, __a0: ghidra.docking.settings.Settings) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setValue(self, settings: ghidra.docking.settings.Settings, value: unicode) -> None:
        """
        Sets the given value into the given settings object using this settingsDefinition as the key.
        @param settings the settings object to store the value in.
        @param value the value to store in the settings object using this settingsDefinition as the key.
        """
        ...

    def supportsSuggestedValues(self) -> bool:
        """
        Determine if this settings definition supports suggested values.
         See {@link #getSuggestedValues(Settings)}.
        @return true if suggested values are supported, else false.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def description(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @property
    def storageKey(self) -> unicode: ...
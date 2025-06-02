from typing import List
import ghidra.docking.settings
import java.lang
import java.util.function


class SettingsDefinition(object):
    """
    Generic interface for defining display options on data and dataTypes.  Uses
     Settings objects to store values which are interpreted by SettingsDefinition objects.
    """









    def clear(self, settings: ghidra.docking.settings.Settings) -> None:
        """
        Removes any values in the given settings object assocated with this settings definition
        @param settings the settings object to be cleared.
        """
        ...

    @staticmethod
    def concat(settings: List[ghidra.docking.settings.SettingsDefinition], additional: List[ghidra.docking.settings.SettingsDefinition]) -> List[ghidra.docking.settings.SettingsDefinition]:
        """
        Create a new list of {@link SettingsDefinition}s by concat'ing a base list with
         a var-arg'ish additional list of setting defs.  Any additional duplicates are discarded.
        @param settings List of settings defs.
        @param additional More settings defs to add
        @return new array with all the settings defs joined together.
        """
        ...

    def copySetting(self, srcSettings: ghidra.docking.settings.Settings, destSettings: ghidra.docking.settings.Settings) -> None:
        """
        Copies any setting value associated with this settings definition from the
         srcSettings settings to the destSettings.
        @param srcSettings the settings to be copied
        @param destSettings the settings to be updated.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def filterSettingsDefinitions(definitions: List[ghidra.docking.settings.SettingsDefinition], filter: java.util.function.Predicate) -> List[ghidra.docking.settings.SettingsDefinition]:
        """
        Get datatype settings definitions for the specified datatype exclusive of any default-use-only definitions.
        @param definitions settings definitions to be filtered
        @param filter callback which determines if definition should be included in returned array
        @return filtered settings definitions
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        Returns a description of this settings definition
        @return setting description
        """
        ...

    def getName(self) -> unicode:
        """
        Returns the display name of this SettingsDefinition
        @return display name for setting
        """
        ...

    def getStorageKey(self) -> unicode:
        """
        Get the {@link Settings} key which is used when storing a key/value entry.
        @return settings storage key
        """
        ...

    def getValueString(self, settings: ghidra.docking.settings.Settings) -> unicode:
        """
        Get the setting value as a string which corresponds to this definition.
         A default value string will be returned if a setting has not been stored.
        @param settings settings
        @return value string or null if not set and default has not specified by this definition
        """
        ...

    def hasSameValue(self, settings1: ghidra.docking.settings.Settings, settings2: ghidra.docking.settings.Settings) -> bool:
        """
        Check two settings for equality which correspond to this 
         settings definition.
        @param settings1 first settings
        @param settings2 second settings
        @return true if the same else false
        """
        ...

    def hasValue(self, setting: ghidra.docking.settings.Settings) -> bool:
        """
        Determine if a setting value has been stored
        @param setting stored settings
        @return true if a value has been stored, else false
        """
        ...

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
    def description(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @property
    def storageKey(self) -> unicode: ...
from typing import List
import ghidra.docking.settings
import java.lang
import java.util.function


class TypeDefSettingsDefinition(ghidra.docking.settings.SettingsDefinition, object):
    """
    TypeDefSettingsDefinition specifies a SettingsDefinition whose
     use as a TypeDef setting will be available for use within a non-Program 
     DataType archive.  Such settings will be considered for DataType equivalence checks and
     preserved during DataType cloning and resolve processing.  As such, these settings
     are only currently supported as a default-setting on a TypeDef
     (see DataType#getDefaultSettings()) and do not support component-specific 
     or data-instance use.
 
     NOTE: Full support for this type of setting has only been fully implemented for TypeDef
     in support. There may be quite a few obstacles to overcome when introducing such 
     settings to a different datatype.
    """









    def clear(self, __a0: ghidra.docking.settings.Settings) -> None: ...

    @staticmethod
    def concat(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: List[ghidra.docking.settings.SettingsDefinition]) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def copySetting(self, __a0: ghidra.docking.settings.Settings, __a1: ghidra.docking.settings.Settings) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def filterSettingsDefinitions(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: java.util.function.Predicate) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getAttributeSpecification(self, settings: ghidra.docking.settings.Settings) -> unicode:
        """
        Get the {@link TypeDef} attribute specification for this setting and its
         current value.
        @param settings typedef settings
        @return attribute specification or null if not currently set.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def getStorageKey(self) -> unicode: ...

    def getValueString(self, __a0: ghidra.docking.settings.Settings) -> unicode: ...

    def hasSameValue(self, __a0: ghidra.docking.settings.Settings, __a1: ghidra.docking.settings.Settings) -> bool: ...

    def hasValue(self, __a0: ghidra.docking.settings.Settings) -> bool: ...

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
from typing import List
import ghidra.docking.settings
import java.lang


class Settings(object):
    """
    Settings objects store name-value pairs.  Each SettingsDefinition defines one
     or more names to use to store values in settings objects.  Exactly what type
     of value and how to interpret the value is done by the SettingsDefinition object.
    """

    EMPTY_STRING_ARRAY: List[unicode] = array(java.lang.String)







    def clearAllSettings(self) -> None:
        """
        Removes all name-value pairs from this settings object
        """
        ...

    def clearSetting(self, name: unicode) -> None:
        """
        Removes any value associated with the given name
        @param name the key to remove any association
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings:
        """
        Returns the underlying default settings for these settings or null if there are none
        @return underlying default settings or null
        """
        ...

    def getLong(self, name: unicode) -> long:
        """
        Gets the Long value associated with the given name
        @param name the key used to retrieve a value
        @return the Long value for a key
        """
        ...

    def getNames(self) -> List[unicode]:
        """
        Get this list of keys that currently have values associated with them
        @return an array of string keys.
        """
        ...

    def getString(self, name: unicode) -> unicode:
        """
        Gets the String value associated with the given name
        @param name the key used to retrieve a value
        @return the String value for a key
        """
        ...

    def getSuggestedValues(self, settingsDefinition: ghidra.docking.settings.StringSettingsDefinition) -> List[unicode]:
        """
        Get an array of suggested values for the specified string settings definition.
        @param settingsDefinition string settings definition
        @return suggested values array (may be empty)
        """
        ...

    def getValue(self, name: unicode) -> object:
        """
        Gets the object associated with the given name
        @param name the key used to retrieve a value
        @return the object associated with a given key
        """
        ...

    def hashCode(self) -> int: ...

    def isChangeAllowed(self, settingsDefinition: ghidra.docking.settings.SettingsDefinition) -> bool:
        """
        Determine if a settings change corresponding to the specified 
         settingsDefinition is permitted.
        @param settingsDefinition settings definition
        @return true if change permitted else false
        """
        ...

    def isEmpty(self) -> bool:
        """
        Returns true if there are no key-value pairs stored in this settings object.
         This is not a reflection of the underlying default settings which may still
         contain a key-value pair when this settings object is empty.
        @return true if there are no key-value pairs stored in this settings object
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setLong(self, name: unicode, value: long) -> None:
        """
        Associates the given long value with the name.
         Note that an attempted setting change may be ignored if prohibited
         (e.g., immutable Settings, undefined setting name).
        @param name the key
        @param value the value associated with the key
        """
        ...

    def setString(self, name: unicode, value: unicode) -> None:
        """
        Associates the given String value with the name.
         Note that an attempted setting change may be ignored if prohibited
         (e.g., immutable Settings, undefined setting name).
        @param name the key
        @param value the value associated with the key
        """
        ...

    def setValue(self, name: unicode, value: object) -> None:
        """
        Associates the given object with the name.
         Note that an attempted setting change may be ignored if prohibited
         (e.g., immutable Settings, undefined setting name).
        @param name the key
        @param value the value to associate with the key
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
    def defaultSettings(self) -> ghidra.docking.settings.Settings: ...

    @property
    def empty(self) -> bool: ...

    @property
    def names(self) -> List[unicode]: ...
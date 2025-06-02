import java.lang
import java.util


class Attributed(object):




    def __init__(self): ...



    def clear(self) -> None:
        """
        removes all key/value mappings
        """
        ...

    def entrySet(self) -> java.util.Set:
        """
        Returns a {@link Set} containing the key/value entry associations
        @return a {@link Set} containing the key/value entry associations
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAttribute(self, key: unicode) -> unicode:
        """
        gets the value of the given attribute name
        @param key attribute name
        @return the mapped value for the supplied key
        """
        ...

    def getAttributes(self) -> java.util.Map:
        """
        Returns an unmodifiable view of the attribute map
        @return an unmodifiable view of the attribute map
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        gets the description of this Attributed object.
        @return the description of this Attributed object.
        """
        ...

    def hasAttribute(self, key: unicode) -> bool:
        """
        Returns true if there is an attribute with that name
        @param key attribute key
        @return true if there is an attribute with that name
        """
        ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool:
        """
        Return true if there are no attributes
        @return true if there are no mapped attributes
        """
        ...

    def keys(self) -> java.util.Set:
        """
        Returns the keys for the attributes
        @return the keys for the attributes
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def putAttributes(self, map: java.util.Map) -> None:
        """
        Adds all the key/value pairs from the given map as attributes
        @param map a map of key/values to add as attributes
        """
        ...

    def removeAttribute(self, key: unicode) -> unicode:
        """
        Removes the attribute with the given key
        @param key attribute key
        @return the value of the removed attribute
        """
        ...

    def setAttribute(self, key: unicode, value: unicode) -> unicode:
        """
        Sets the attribute with the given key and value
        @param key attribute key
        @param value attribute value
        @return the previous value of the attribute
        """
        ...

    def setDescription(self, value: unicode) -> unicode:
        """
        Sets a description for this Attributed object
        @param value text that provides a description for this Attributed object. 
         The text can be either a plain string or an HTML string.
        @return the previously set description
        """
        ...

    def size(self) -> int:
        """
        Returns the number of attributes defined
        @return the number of attributes defined
        """
        ...

    def toString(self) -> unicode: ...

    def values(self) -> java.util.Collection:
        """
        Returns the attribute values
        @return the attribute values
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def attributes(self) -> java.util.Map: ...

    @property
    def description(self) -> unicode: ...

    @description.setter
    def description(self, value: unicode) -> None: ...

    @property
    def empty(self) -> bool: ...
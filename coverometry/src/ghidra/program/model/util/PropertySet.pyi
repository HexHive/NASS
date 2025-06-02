from typing import Iterator
import ghidra.util
import java.lang


class PropertySet(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getIntProperty(self, name: unicode) -> int:
        """
        Get the int property for name.
        @param name the name of the property
        @return integer property value property has been set
        @throws NoValueException if there is not name property
         for this code unit
        @throws TypeMismatchException if a propertyMap named propertyName
         exists but is not an IntPropertyMap.
        """
        ...

    def getObjectProperty(self, name: unicode) -> ghidra.util.Saveable:
        """
        Get the object property for name; returns null if
         there is no name property for this code unit.
        @param name the name of the property
        @return {@link Saveable} property value, with map-specific implementation class, or null.
        @throws TypeMismatchException if a propertyMap named propertyName
         exists but is not an ObjectPropertyMap.
        """
        ...

    def getStringProperty(self, name: unicode) -> unicode:
        """
        Get the string property for name; returns null if
         there is no name property for this code unit.
        @param name the name of the property
        @return string property value or null
        @throws TypeMismatchException if a propertyMap named propertyName
         exists but is not an StringPropertyMap.
        """
        ...

    def getVoidProperty(self, name: unicode) -> bool:
        """
        Returns whether this code unit is marked as having the
         name property.
        @param name the name of the property
        @return true if property has been set, else false
        @throws TypeMismatchException if a propertyMap named propertyName
         exists but is not an VoidPropertyMap.
        """
        ...

    def hasProperty(self, name: unicode) -> bool:
        """
        Returns true if the codeunit has the given property defined.
         This method works for all property map types.
        @param name the name of the property
        @return true if property has been set, else false
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def propertyNames(self) -> Iterator[unicode]:
        """
        Get an iterator over the property names which have values applied.
        @return iterator of all property map names which have values applied
        """
        ...

    def removeProperty(self, name: unicode) -> None:
        """
        Remove the property value associated with the given name .
        @param name the name of the property
        """
        ...

    @overload
    def setProperty(self, name: unicode) -> None:
        """
        Set the named property.  This method is used for "void" properites. The
         property is either set or not set - there is no value
        @param name the name of the property.
        @throws TypeMismatchException if a propertyMap named propertyName
         exists but is not a VoidPropertyMap.
        """
        ...

    @overload
    def setProperty(self, name: unicode, value: int) -> None:
        """
        Set the named integer property with the given value.
        @param name the name of the property.
        @param value value to be stored.
        @throws TypeMismatchException if a propertyMap named propertyName
         exists but is not an IntPropertyMap.
        """
        ...

    @overload
    def setProperty(self, name: unicode, value: unicode) -> None:
        """
        Set the named string property with the given value.
        @param name the name of the property.
        @param value value to be stored.
        @throws TypeMismatchException if a propertyMap named propertyName
         exists but is not a StringPropertyMap.
        """
        ...

    @overload
    def setProperty(self, __a0: unicode, __a1: ghidra.util.Saveable) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def property(self) -> None: ...  # No getter available.

    @property.setter
    def property(self, value: unicode) -> None: ...
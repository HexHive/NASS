from typing import List
import db
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.model.util
import java.lang
import java.util


class ProgramUserData(ghidra.framework.model.UserData, object):








    def endTransaction(self, transactionID: int) -> None:
        """
        End a previously started transaction
        @param transactionID the id of the transaction to close
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBooleanProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.VoidPropertyMap:
        """
        Get a address-based Boolean property map
        @param owner name of property owner (e.g., plugin name)
        @param propertyName the name of property map
        @param create creates the property map if it does not exist
        @return property map
        @throws PropertyTypeMismatchException if a conflicting map definition was found
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getIntProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.IntPropertyMap:
        """
        Get a address-based Integer property map
        @param owner name of property owner (e.g., plugin name)
        @param propertyName the name of property map
        @param create creates the property map if it does not exist
        @return property map
        @throws PropertyTypeMismatchException if a conflicting map definition was found
        """
        ...

    def getLongProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.LongPropertyMap:
        """
        Get a address-based Long property map
        @param owner name of property owner (e.g., plugin name)
        @param propertyName the name of property map
        @param create creates the property map if it does not exist
        @return property map
        @throws PropertyTypeMismatchException if a conflicting map definition was found
        """
        ...

    def getObjectProperty(self, owner: unicode, propertyName: unicode, saveableObjectClass: java.lang.Class, create: bool) -> ghidra.program.model.util.ObjectPropertyMap:
        """
        Get a address-based Saveable-object property map
        @param owner name of property owner (e.g., plugin name)
        @param propertyName the name of property map
        @param saveableObjectClass the class type for the object property map
        @param create creates the property map if it does not exist
        @param <T> {@link Saveable} property value type
        @return property map
        @throws PropertyTypeMismatchException if a conflicting map definition was found
        """
        ...

    def getOptions(self, optionsName: unicode) -> ghidra.framework.options.Options:
        """
        Get the Options for the given optionsName
        @param optionsName the name of the options options to retrieve
        @return The options for the given name
        """
        ...

    def getOptionsNames(self) -> List[unicode]:
        """
        Returns all names of all the Options objects store in the user data
        @return all names of all the Options objects store in the user data
        """
        ...

    def getProperties(self, owner: unicode) -> List[ghidra.program.model.util.PropertyMap]:
        """
        Get all property maps associated with a specific owner.
        @param owner name of property owner (e.g., plugin name)
        @return list of property maps
        """
        ...

    def getPropertyOwners(self) -> List[unicode]:
        """
        Returns list of all property owners for which property maps have been defined.
        @return list of all property owners for which property maps have been defined.
        """
        ...

    @overload
    def getStringProperty(self, propertyName: unicode, defaultValue: unicode) -> unicode:
        """
        Gets the value for the given property name
        @param propertyName the name of the string property to retrieve
        @param defaultValue the value to return if there is no saved value for the given name
        @return the value for the given property name
        """
        ...

    @overload
    def getStringProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.StringPropertyMap:
        """
        Get a address-based String property map
        @param owner name of property owner (e.g., plugin name)
        @param propertyName the name of property map
        @param create creates the property map if it does not exist
        @return the property map for the given name
        @throws PropertyTypeMismatchException if a conflicting map definition was found
        """
        ...

    def getStringPropertyNames(self) -> java.util.Set:
        """
        Returns a set of all String properties that have been set on this ProgramUserData object
        @return a set of all String properties that have been set on this ProgramUserData object
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openTransaction(self) -> db.Transaction:
        """
        Open new transaction.  This should generally be done with a try-with-resources block:
         <pre>
         try (Transaction tx = pud.openTransaction(description)) {
         	// ... Do something
         }
         </pre>
        @return transaction object
        @throws IllegalStateException if this {@link ProgramUserData} has already been closed.
        """
        ...

    def removeStringProperty(self, propertyName: unicode) -> unicode:
        """
        Removes the String property with the given name;
        @param propertyName the name of the property to remove;
        @return returns the value of the property that was removed or null if the property doesn't
         exist
        """
        ...

    def setStringProperty(self, propertyName: unicode, value: unicode) -> None:
        """
        Sets the given String property
        @param propertyName the name of the property
        @param value the value of the property
        """
        ...

    def startTransaction(self) -> int:
        """
        Start a transaction prior to changing any properties
        @return transaction ID needed for endTransaction
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
    def optionsNames(self) -> List[object]: ...

    @property
    def propertyOwners(self) -> List[object]: ...

    @property
    def stringPropertyNames(self) -> java.util.Set: ...
from typing import List
import generic.jar
import ghidra.app.plugin.core.datamgr.archive
import ghidra.app.services
import ghidra.framework.model
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import java.io
import java.lang
import java.util
import javax.swing.tree


class DataTypeManagerService(ghidra.app.services.DataTypeQueryService, ghidra.app.services.DataTypeArchiveService, object):
    """
    Service to provide list of cycle groups and data types identified as
     "favorites." Favorites will show up on the popup menu for creating
     data and defining function return types and parameters.
    """









    def addDataTypeManagerChangeListener(self, listener: ghidra.program.model.data.DataTypeManagerChangeListener) -> None:
        """
        Adds a listener to be notified when changes occur to any open datatype manager.
        @param listener the listener to be added.
        """
        ...

    def closeArchive(self, __a0: ghidra.program.model.data.DataTypeManager) -> None: ...

    def edit(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        Pop up an editor dialog for the given data type.
        @param dt data type that either a Structure or a Union; built in types cannot be edited
        @throws IllegalArgumentException if the given has not been resolved by a DataTypeManager;
                 in other words, if {@link DataType#getDataTypeManager()} returns null.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBuiltInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getDataType(self, __a0: unicode) -> ghidra.program.model.data.DataType: ...

    @overload
    def getDataType(self, selectedPath: javax.swing.tree.TreePath) -> ghidra.program.model.data.DataType:
        """
        Shows the user a dialog that allows them to choose a data type from a tree of all available
         data types.
        @param selectedPath An optional tree path to select in the tree
        @return A data type chosen by the user
        """
        ...

    def getDataTypeManagers(self) -> List[ghidra.program.model.data.DataTypeManager]: ...

    def getEditorHelpLocation(self, dataType: ghidra.program.model.data.DataType) -> ghidra.util.HelpLocation:
        """
        Gets the location of the help for editing the specified data type.
        @param dataType the data type to be edited.
        @return the help location for editing the data type.
        """
        ...

    def getFavorites(self) -> List[ghidra.program.model.data.DataType]:
        """
        Get the data types marked as favorites that will show up on
         a popup menu.
        @return list of favorite datatypes
        """
        ...

    def getPossibleEquateNames(self, value: long) -> java.util.Set:
        """
        Examines all enum dataTypes for items that match the given value. Returns a list of Strings
         that might make sense for the given value.
        @param value the value to search for.
        @return the list of enum item names that match the given value
        """
        ...

    def getRecentlyUsed(self) -> ghidra.program.model.data.DataType:
        """
        Get the data type that was most recently used to apply data to a
         Program.
        @return data type that was most recently used
        """
        ...

    def getSelectedDatatypes(self) -> List[ghidra.program.model.data.DataType]:
        """
        Returns the list of data types that are currently selected in the data types tree
        @return the list of data types that are currently selected in the data types tree
        """
        ...

    def getSortedDataTypeList(self) -> List[object]: ...

    def hashCode(self) -> int: ...

    def isEditable(self, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Determine if the indicated data type can be edited 
         (i.e. it has an editor that this service knows how to invoke).
        @param dt data type to be edited
        @return true if this service can invoke an editor for changing the data type.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def openArchive(self, __a0: ghidra.program.model.listing.DataTypeArchive) -> ghidra.app.plugin.core.datamgr.archive.Archive: ...

    @overload
    def openArchive(self, __a0: generic.jar.ResourceFile, __a1: bool) -> ghidra.program.model.data.DataTypeManager: ...

    @overload
    def openArchive(self, __a0: java.io.File, __a1: bool) -> ghidra.app.plugin.core.datamgr.archive.Archive: ...

    @overload
    def openArchive(self, __a0: ghidra.framework.model.DomainFile, __a1: ghidra.util.task.TaskMonitor) -> ghidra.program.model.data.DataTypeManager: ...

    def openDataTypeArchive(self, __a0: unicode) -> ghidra.program.model.data.DataTypeManager: ...

    def removeDataTypeManagerChangeListener(self, listener: ghidra.program.model.data.DataTypeManagerChangeListener) -> None:
        """
        Removes the given listener from receiving dataTypeManger change notifications.
        @param listener the listener to be removed.
        """
        ...

    def setDataTypeSelected(self, dataType: ghidra.program.model.data.DataType) -> None:
        """
        Selects the given data type in the display of data types.  A null <code>dataType</code>
         value will clear the current selection.
        @param dataType The data type to select.
        """
        ...

    def setRecentlyUsed(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        Set the given data type as the most recently used to apply a
         data type to a Program.
        @param dt data type that was most recently used
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
    def builtInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def dataTypeManagers(self) -> List[ghidra.program.model.data.DataTypeManager]: ...

    @property
    def dataTypeSelected(self) -> None: ...  # No getter available.

    @dataTypeSelected.setter
    def dataTypeSelected(self, value: ghidra.program.model.data.DataType) -> None: ...

    @property
    def favorites(self) -> List[object]: ...

    @property
    def recentlyUsed(self) -> ghidra.program.model.data.DataType: ...

    @recentlyUsed.setter
    def recentlyUsed(self, value: ghidra.program.model.data.DataType) -> None: ...

    @property
    def selectedDatatypes(self) -> List[object]: ...

    @property
    def sortedDataTypeList(self) -> List[object]: ...
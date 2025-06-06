from typing import List
import docking
import ghidra.framework.main.datatable
import ghidra.framework.model
import java.awt
import java.awt.event
import java.lang


class ProjectDataContext(docking.DefaultActionContext, ghidra.framework.main.datatable.DomainFileContext):
    """
    A context that understands files that live in a Project.  Most of the clients of
     this context will use its notion of selected DomainFiles and folders.
    """





    def __init__(self, __a0: docking.ComponentProvider, __a1: ghidra.framework.model.ProjectData, __a2: object, __a3: List[object], __a4: List[object], __a5: java.awt.Component, __a6: bool): ...



    def containsRootFolder(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> java.awt.Component: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getEventClickModifiers(self) -> int: ...

    def getFileCount(self) -> int: ...

    def getFolderCount(self) -> int: ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getProjectData(self) -> ghidra.framework.model.ProjectData: ...

    def getSelectedFiles(self) -> List[ghidra.framework.model.DomainFile]: ...

    def getSelectedFolders(self) -> List[ghidra.framework.model.DomainFolder]: ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def hasAnyEventClickModifiers(self, modifiersMask: int) -> bool: ...

    def hasExactlyOneFileOrFolder(self) -> bool: ...

    def hasOneOrMoreFilesAndFolders(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isInActiveProject(self) -> bool: ...

    def isReadOnlyProject(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setContextObject(self, contextObject: object) -> docking.DefaultActionContext: ...

    def setEventClickModifiers(self, modifiers: int) -> None: ...

    def setMouseEvent(self, e: java.awt.event.MouseEvent) -> docking.DefaultActionContext: ...

    def setSourceObject(self, sourceObject: object) -> docking.DefaultActionContext: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def component(self) -> java.awt.Component: ...

    @property
    def fileCount(self) -> int: ...

    @property
    def folderCount(self) -> int: ...

    @property
    def inActiveProject(self) -> bool: ...

    @property
    def projectData(self) -> ghidra.framework.model.ProjectData: ...

    @property
    def readOnlyProject(self) -> bool: ...

    @property
    def selectedFiles(self) -> List[object]: ...

    @property
    def selectedFolders(self) -> List[object]: ...
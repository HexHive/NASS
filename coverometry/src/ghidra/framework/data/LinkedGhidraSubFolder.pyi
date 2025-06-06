from typing import List
import ghidra.framework.data
import ghidra.framework.model
import ghidra.util.task
import java.io
import java.lang
import java.net
import javax.swing


class LinkedGhidraSubFolder(object, ghidra.framework.model.LinkedDomainFolder):








    def compareTo(self, __a0: object) -> int: ...

    def copyTo(self, newParent: ghidra.framework.model.DomainFolder, monitor: ghidra.util.task.TaskMonitor) -> ghidra.framework.model.DomainFolder: ...

    def copyToAsLink(self, newParent: ghidra.framework.model.DomainFolder) -> ghidra.framework.model.DomainFile: ...

    @overload
    def createFile(self, name: unicode, obj: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor) -> ghidra.framework.model.DomainFile: ...

    @overload
    def createFile(self, name: unicode, packFile: java.io.File, monitor: ghidra.util.task.TaskMonitor) -> ghidra.framework.model.DomainFile: ...

    def createFolder(self, name: unicode) -> ghidra.framework.model.DomainFolder: ...

    def delete(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFile(self, name: unicode) -> ghidra.framework.model.DomainFile: ...

    def getFiles(self) -> List[ghidra.framework.model.DomainFile]: ...

    def getFolder(self, name: unicode) -> ghidra.framework.data.LinkedGhidraSubFolder: ...

    def getFolders(self) -> List[ghidra.framework.data.LinkedGhidraSubFolder]: ...

    def getIcon(self, isOpen: bool) -> javax.swing.Icon: ...

    def getLinkedFolder(self) -> ghidra.framework.model.DomainFolder: ...

    def getLocalProjectURL(self) -> java.net.URL: ...

    def getName(self) -> unicode: ...

    def getParent(self) -> ghidra.framework.model.DomainFolder: ...

    def getPathname(self) -> unicode: ...

    def getProjectData(self) -> ghidra.framework.model.ProjectData: ...

    def getProjectLocator(self) -> ghidra.framework.model.ProjectLocator: ...

    def getSharedProjectURL(self) -> java.net.URL: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def isInWritableProject(self) -> bool: ...

    def isLinked(self) -> bool: ...

    def moveTo(self, newParent: ghidra.framework.model.DomainFolder) -> ghidra.framework.model.DomainFolder: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setActive(self) -> None: ...

    def setName(self, newName: unicode) -> ghidra.framework.model.DomainFolder: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


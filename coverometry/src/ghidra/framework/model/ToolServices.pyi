from typing import List
import ghidra.framework.model
import ghidra.framework.plugintool
import java.io
import java.lang
import java.net
import java.util


class ToolServices(object):
    """
    Services that the Tool uses.
    """

    DEFAULT_TOOLNAME: unicode = u'DefaultTool'







    def canAutoSave(self, tool: ghidra.framework.plugintool.PluginTool) -> bool:
        """
        Returns true if this tool should be saved base on the state of other running instances of
         the same tool
        @param tool the tool to check for saving
        @return true if the tool should be saved
        """
        ...

    def closeTool(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        """
        Notify the framework that the tool is closing.
        @param tool tool that is closing
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def exportTool(self, tool: ghidra.framework.model.ToolTemplate) -> java.io.File:
        """
        Save the tool to the given location on the local file system.
        @param tool the tool template to write
        @return the file to which the tool was saved
        @throws FileNotFoundException thrown if the file's directory doesn't exist.
        @throws IOException thrown if there is an error writing the file.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCompatibleTools(self, domainClass: java.lang.Class) -> java.util.Set:
        """
        Returns a set of tools that can open the given domain file class.
        @param domainClass The domain file class type for which to get tools
        @return the tools
        """
        ...

    def getContentTypeToolAssociations(self) -> java.util.Set:
        """
        Returns the {@link ToolAssociationInfo associations}, which describe content
         types and the tools used to open them, for all content types known to the system.
        @return the associations
        @see #setContentTypeToolAssociations(Set)
        """
        ...

    @overload
    def getDefaultToolTemplate(self, contentType: unicode) -> ghidra.framework.model.ToolTemplate:
        """
        Returns the default/preferred tool template which should be used to open the specified
         domain file content type, whether defined by the user or the system default.
        @param contentType The content type whose preferred tool should be found.
        @return The preferred tool that should be used to open the given file or null if none found.
        """
        ...

    @overload
    def getDefaultToolTemplate(self, domainFile: ghidra.framework.model.DomainFile) -> ghidra.framework.model.ToolTemplate:
        """
        Returns the default/preferred tool template which should be used to open the specified
         domain file, whether defined by the user or the system default.
        @param domainFile The file whose preferred tool should be found.
        @return The preferred tool that should be used to open the given file or null if none found.
        """
        ...

    def getRunningTools(self) -> List[ghidra.framework.plugintool.PluginTool]:
        """
        Return array of running tools
        @return array of Tools
        """
        ...

    def getToolChest(self) -> ghidra.framework.model.ToolChest:
        """
        Get the tool chest for the project
        @return the tool chest
        """
        ...

    def hashCode(self) -> int: ...

    def launchDefaultTool(self, domainFiles: java.util.Collection) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the default {@link PluginTool tool} and open the specified domainFiles.
         NOTE: running tool reuse is implementation dependent
        @param domainFiles the files to open.  A null or empty list will results in an immediate 
         return of a null {@link PluginTool}.  Null entries are not permitted.
        @return the launched tool.  Null returned if a suitable default tool
         for the file content type was not found or failed to launch.
        """
        ...

    def launchDefaultToolWithURL(self, ghidraUrl: java.net.URL) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the default tool and open the specified Ghidra URL resource.
         The tool chosen will be based upon the content type of the specified resource.
         NOTE: running tool re-use is implementation dependent
        @param ghidraUrl resource to be opened (see {@link GhidraURL})
        @return the launched tool.  Null returned if a failure occurs while accessing the specified
         resource or a suitable default tool for the file content type was not found.
        @throws IllegalArgumentException if URL protocol is not supported.  Currently, only
         the {@code ghidra} protocol is supported.
        """
        ...

    def launchTool(self, toolName: unicode, domainFiles: java.util.Collection) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the {@link PluginTool tool} with the given name and open the specified domainFiles.
         Only those domainFiles with a content type supported by the specified tool will be opened.
         NOTE: running tool reuse is implementation dependent.
        @param toolName name of the {@link ToolTemplate tool template} to launch or re-use
        @param domainFiles the files to open; may be null or empty.  Null entries are not permitted.
        @return the resulting {@link PluginTool tool} or null if the specified tool was not found
         or failed to launch
        """
        ...

    def launchToolWithURL(self, toolName: unicode, ghidraUrl: java.net.URL) -> ghidra.framework.plugintool.PluginTool:
        """
        Launch the tool with the given name and attempt to open the specified Ghidra URL resource.
        @param toolName name of the tool to launch
        @param ghidraUrl resource to be opened (see {@link GhidraURL})
        @return the requested tool or null if the specified tool not found.
        @throws IllegalArgumentException if URL protocol is not supported.  Currently, only
         the {@code ghidra} protocol is supported.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def saveTool(self, tool: ghidra.framework.plugintool.PluginTool) -> None:
        """
        Saves the tool's configuration in the standard
         tool location.
        @param tool tool to save.
        """
        ...

    def setContentTypeToolAssociations(self, infos: java.util.Set) -> None:
        """
        Sets the  {@link ToolAssociationInfo associations}, which describe content
         types and the tools used to open them, for the system.
        @param infos The associations to be applied
        @see #getContentTypeToolAssociations()
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
    def contentTypeToolAssociations(self) -> java.util.Set: ...

    @contentTypeToolAssociations.setter
    def contentTypeToolAssociations(self, value: java.util.Set) -> None: ...

    @property
    def runningTools(self) -> List[ghidra.framework.plugintool.PluginTool]: ...

    @property
    def toolChest(self) -> ghidra.framework.model.ToolChest: ...
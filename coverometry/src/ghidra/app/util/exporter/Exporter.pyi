from typing import List
import ghidra.app.util
import ghidra.app.util.importer
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.task
import java.io
import java.lang


class Exporter(object, ghidra.util.classfinder.ExtensionPoint):
    """
    The interface that all exporters must implement.
    """









    def canExportDomainFile(self, domainFile: ghidra.framework.model.DomainFile) -> bool:
        """
        Returns true if exporter can export the specified {@link DomainFile} without instantiating 
         a {@link DomainObject}.  This method should be used prior to exporting using the
         {@link #export(File, DomainFile, TaskMonitor)} method.  All exporter capable of a 
         {@link DomainFile} export must also support a export of a {@link DomainObject} so that any
         possible data modification/upgrade is included within resulting export.
        @param domainFile domain file
        @return true if export can occur else false if not
        """
        ...

    @overload
    def canExportDomainObject(self, domainObject: ghidra.framework.model.DomainObject) -> bool:
        """
        Returns true if this exporter knows how to export the given domain object considering any
         constraints based on the specific makeup of the object.  This method should be used prior to
         exporting using the {@link #export(File, DomainObject, AddressSetView, TaskMonitor)} method.
        @param domainObject the domain object to test for exporting.
        @return true if this exporter knows how to export the given domain object.
        """
        ...

    @overload
    def canExportDomainObject(self, domainObjectClass: java.lang.Class) -> bool:
        """
        Returns true if this exporter is capable of exporting the given domain file/object content
         type.  For example, some exporters have the ability to export programs, other exporters can 
         export project data type archives.
         <p>
         NOTE: This method should only be used as a preliminary check, if neccessary, to identify 
         exporter implementations that are capable of handling a specified content type/class.  Prior
         to export a final check should be performed based on the export or either a 
         {@link DomainFile} or {@link DomainObject}:
         <p>
         {@link DomainFile} export - the method {@link #canExportDomainFile(DomainFile)} should be 
         used to verify a direct project file export is possible using the 
         {@link #export(File, DomainFile, TaskMonitor)} method.
         <p>
         {@link DomainObject} export - the method {@link #canExportDomainObject(DomainObject)} should 
         be used to verify an export of a specific object is possible using the 
         {@link #export(File, DomainObject, AddressSetView, TaskMonitor)} method.
 
         avoid opening DomainFile when possible.
        @param domainObjectClass the class of the domain object to test for exporting.
        @return true if this exporter knows how to export the given domain object type.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def export(self, file: java.io.File, domainFile: ghidra.framework.model.DomainFile, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Actually does the work of exporting a domain file, if supported (see
         {@link #canExportDomainFile(DomainFile)}).  Export is performed without instantiation of a
         {@link DomainObject}.
        @param file the output file to write the exported info
        @param domainFile the domain file to be exported (e.g., packed DB file)
        @param monitor the task monitor
        @return true if the file was successfully exported; otherwise, false.  If the file
           was not successfully exported, the message log should be checked to find the source of
           the error.
        @throws ExporterException if export error occurs
        @throws IOException if an IO error occurs
        """
        ...

    @overload
    def export(self, file: java.io.File, domainObj: ghidra.framework.model.DomainObject, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Actually does the work of exporting a {@link DomainObject}.  Export will include all 
         saved and unsaved modifications which may have been made to the object.
        @param file the output file to write the exported info
        @param domainObj the domain object to export
        @param addrSet the address set if only a portion of the program should be exported
                            NOTE: see {@link #supportsAddressRestrictedExport()}.
        @param monitor the task monitor
        @return true if the program was successfully exported; otherwise, false.  If the program
           was not successfully exported, the message log should be checked to find the source of
           the error.
        @throws ExporterException if export error occurs
        @throws IOException if an IO error occurs
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultFileExtension(self) -> unicode:
        """
        Returns the default extension for this exporter.
         For example, .html for .xml.
        @return the default extension for this exporter
        """
        ...

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the help location for this exporter.
         It should return null only if no help documentation exists.
        @return the help location for this exporter
        """
        ...

    def getMessageLog(self) -> ghidra.app.util.importer.MessageLog:
        """
        Returns the message log the may have been created during an export.
         The message log is used to log warnings and other non-critical messages.
        @return the message log
        """
        ...

    def getName(self) -> unicode:
        """
        Returns the display name of this exporter.
        @return the display name of this exporter
        """
        ...

    def getOptions(self, domainObjectService: ghidra.app.util.DomainObjectService) -> List[ghidra.app.util.Option]:
        """
        Returns the available options for this exporter.
         The program is needed because some exporters
         may have options that vary depending on the specific
         program being exported.
        @param domainObjectService a service for retrieving the applicable domainObject.
        @return the available options for this exporter
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setExporterServiceProvider(self, provider: ghidra.framework.plugintool.ServiceProvider) -> None:
        """
        Sets the exporter service provider.
        @param provider the exporter service provider
        """
        ...

    def setOptions(self, __a0: List[object]) -> None: ...

    def supportsAddressRestrictedExport(self) -> bool:
        """
        Returns true if this exporter can perform a restricted export of a {@link DomainObject}
         based upon a specified {@link AddressSetView}.
        @return true if this exporter can export less than the entire domain file.
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
    def defaultFileExtension(self) -> unicode: ...

    @property
    def exporterServiceProvider(self) -> None: ...  # No getter available.

    @exporterServiceProvider.setter
    def exporterServiceProvider(self, value: ghidra.framework.plugintool.ServiceProvider) -> None: ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation: ...

    @property
    def messageLog(self) -> ghidra.app.util.importer.MessageLog: ...

    @property
    def name(self) -> unicode: ...

    @property
    def options(self) -> None: ...  # No getter available.

    @options.setter
    def options(self, value: List[object]) -> None: ...
from typing import List
import ghidra.app.util
import ghidra.app.util.exporter
import ghidra.app.util.importer
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.util
import ghidra.util.task
import java.io
import java.lang


class GzfExporter(ghidra.app.util.exporter.Exporter):
    EXTENSION: unicode = u'gzf'
    NAME: unicode = u'Ghidra Zip File'
    SUFFIX: unicode = u'.gzf'



    def __init__(self): ...



    def canExportDomainFile(self, domainFile: ghidra.framework.model.DomainFile) -> bool: ...

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
    def canExportDomainObject(self, domainObjectClass: java.lang.Class) -> bool: ...

    def equals(self, obj: object) -> bool: ...

    @overload
    def export(self, file: java.io.File, domainFile: ghidra.framework.model.DomainFile, monitor: ghidra.util.task.TaskMonitor) -> bool: ...

    @overload
    def export(self, file: java.io.File, domainObj: ghidra.framework.model.DomainObject, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> bool: ...

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

    def getOptions(self, domainObjectService: ghidra.app.util.DomainObjectService) -> List[ghidra.app.util.Option]: ...

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
        Returns false.  GZF export only supports entire database.
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
    def options(self) -> None: ...  # No getter available.

    @options.setter
    def options(self, value: List[object]) -> None: ...
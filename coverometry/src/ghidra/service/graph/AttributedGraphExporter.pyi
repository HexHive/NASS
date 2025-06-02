import ghidra.service.graph
import ghidra.util.classfinder
import java.io
import java.lang


class AttributedGraphExporter(ghidra.util.classfinder.ExtensionPoint, object):
    """
    Interface for exporting AttributedGraphs
    """









    def equals(self, __a0: object) -> bool: ...

    def exportGraph(self, graph: ghidra.service.graph.AttributedGraph, file: java.io.File) -> None:
        """
        Exports the given graph to the given writer
        @param graph the {@link AttributedGraph} to export
        @param file the file to export to
        @throws IOException if there is an error exporting the graph
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDesciption(self) -> unicode:
        """
        Returns a description of the exporter
        @return a description of the exporter
        """
        ...

    def getFileExtension(self) -> unicode:
        """
        Returns the suggested file extension to use for this exporter
        @return the suggested file extension to use for this exporter
        """
        ...

    def getName(self) -> unicode:
        """
        Returns the name of this exporter
        @return the name of this exporter
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def desciption(self) -> unicode: ...

    @property
    def fileExtension(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...
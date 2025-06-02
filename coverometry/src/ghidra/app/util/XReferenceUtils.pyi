from typing import List
import ghidra.app.nav
import ghidra.app.util.query
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import java.lang
import java.util


class XReferenceUtils(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getAllXrefs(location: ghidra.program.util.ProgramLocation) -> java.util.Set:
        """
        Returns all xrefs to the given location.  If in data, then xrefs to the specific data
         component will be returned.  Otherwise, the code unit containing the address of the
         given location will be used as the source of the xrefs.
        @param location the location for which to get xrefs
        @return the xrefs
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOffcutXReferences(cu: ghidra.program.model.listing.CodeUnit, max: int) -> List[ghidra.program.model.symbol.Reference]:
        """
        Returns an array containing all offcut xref references to the specified code unit
        @param cu the code unit to generate the offcut xrefs
        @param max max number of offcut xrefs to get, or -1 to get all offcut references
        @return array of all offcut xrefs to the code unit
        """
        ...

    @overload
    @staticmethod
    def getVariableRefs(__a0: ghidra.program.model.listing.Variable, __a1: List[object], __a2: List[object]) -> None: ...

    @overload
    @staticmethod
    def getVariableRefs(__a0: ghidra.program.model.listing.Variable, __a1: List[object], __a2: List[object], __a3: int) -> None: ...

    @staticmethod
    def getXReferences(cu: ghidra.program.model.listing.CodeUnit, max: int) -> List[ghidra.program.model.symbol.Reference]:
        """
        Returns an array containing the first <b><code>max</code></b>
         direct xref references to the specified code unit.
        @param cu the code unit to generate the xrefs
        @param max max number of xrefs to get, or -1 to get all references
        @return array first <b><code>max</code></b> xrefs to the code unit
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def showXrefs(navigatable: ghidra.app.nav.Navigatable, serviceProvider: ghidra.framework.plugintool.ServiceProvider, service: ghidra.app.util.query.TableService, location: ghidra.program.util.ProgramLocation, xrefs: java.util.Collection) -> None:
        """
        Shows all xrefs to the given location in a new table.
        @param navigatable the navigatable used for navigation from the table
        @param serviceProvider the service provider needed to wire navigation
        @param service the service needed to show the table
        @param location the location for which to find references
        @param xrefs the xrefs to show
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


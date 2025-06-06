import ghidra.app.plugin.core.navigation.locationreferences
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class DataTypeReference(object):
    """
    A container class to hold information about a location that references a DataType.
    """





    def __init__(self, dataType: ghidra.program.model.data.DataType, fieldName: unicode, function: ghidra.program.model.listing.Function, address: ghidra.program.model.address.Address, context: ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext): ...



    def equals(self, obj: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    def getContext(self) -> ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getFunction(self) -> ghidra.program.model.listing.Function: ...

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
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def context(self) -> ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def function(self) -> ghidra.program.model.listing.Function: ...
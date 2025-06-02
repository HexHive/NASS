import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.proxy
import ghidra.program.model.address
import java.lang


class AddressProxy(ghidra.app.util.viewer.proxy.ProxyObj):
    """
    Stores information about an address in a program.
    """





    def __init__(self, model: ghidra.app.util.viewer.listingpanel.ListingModel, addr: ghidra.program.model.address.Address):
        """
        Construct a address proxy
        @param model the model
        @param addr the address to proxy
        """
        ...



    def contains(self, a: ghidra.program.model.address.Address) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getListingLayoutModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        """
        Returns the layout model which corresponds to this field proxy.
        @return the model
        """
        ...

    def getObject(self) -> ghidra.program.model.address.Address: ...

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
    def object(self) -> ghidra.program.model.address.Address: ...
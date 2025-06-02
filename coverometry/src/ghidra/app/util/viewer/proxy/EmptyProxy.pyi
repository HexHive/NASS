import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.proxy
import ghidra.program.model.address
import java.lang


class EmptyProxy(ghidra.app.util.viewer.proxy.ProxyObj):
    """
    Used as proxy for a null value.
    """

    EMPTY_PROXY: ghidra.app.util.viewer.proxy.EmptyProxy = ghidra.app.util.viewer.proxy.EmptyProxy@8fb03a4







    def contains(self, a: ghidra.program.model.address.Address) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getListingLayoutModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel:
        """
        Returns the layout model which corresponds to this field proxy.
        @return the model
        """
        ...

    def getObject(self) -> object: ...

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
    def object(self) -> object: ...
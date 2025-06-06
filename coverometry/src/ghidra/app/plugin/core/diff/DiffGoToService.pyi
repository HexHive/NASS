import ghidra.app.nav
import ghidra.app.services
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.task
import java.lang


class DiffGoToService(object, ghidra.app.services.GoToService):
    VALID_GOTO_CHARS: List[int] = array(char, ['.', ':', '*'])



    def __init__(self, __a0: ghidra.app.services.GoToService, __a1: ghidra.app.plugin.core.diff.ProgramDiffPlugin): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultNavigatable(self) -> ghidra.app.nav.Navigatable: ...

    def getOverrideService(self) -> ghidra.app.services.GoToOverrideService: ...

    @overload
    def goTo(self, __a0: ghidra.program.model.address.Address) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.program.util.ProgramLocation) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.app.nav.Navigatable, __a1: ghidra.program.model.address.Address) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.listing.Program) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.program.util.ProgramLocation, __a1: ghidra.program.model.listing.Program) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.app.nav.Navigatable, __a1: ghidra.program.util.ProgramLocation, __a2: ghidra.program.model.listing.Program) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.app.nav.Navigatable, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.address.Address, __a3: ghidra.program.model.address.Address) -> bool: ...

    @overload
    def goToExternalLocation(self, __a0: ghidra.program.model.symbol.ExternalLocation, __a1: bool) -> bool: ...

    @overload
    def goToExternalLocation(self, __a0: ghidra.app.nav.Navigatable, __a1: ghidra.program.model.symbol.ExternalLocation, __a2: bool) -> bool: ...

    @overload
    def goToQuery(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.app.services.QueryData, __a2: ghidra.app.services.GoToServiceListener, __a3: ghidra.util.task.TaskMonitor) -> bool: ...

    @overload
    def goToQuery(self, __a0: ghidra.app.nav.Navigatable, __a1: ghidra.program.model.address.Address, __a2: ghidra.app.services.QueryData, __a3: ghidra.app.services.GoToServiceListener, __a4: ghidra.util.task.TaskMonitor) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setOverrideService(self, __a0: ghidra.app.services.GoToOverrideService) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def defaultNavigatable(self) -> ghidra.app.nav.Navigatable: ...

    @property
    def overrideService(self) -> ghidra.app.services.GoToOverrideService: ...

    @overrideService.setter
    def overrideService(self, value: ghidra.app.services.GoToOverrideService) -> None: ...
import ghidra.feature.vt.api.main
import ghidra.feature.vt.api.util
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class SimilarDataProgramCorrelatorFactory(ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory):
    MEMORY_MODEL: unicode = u'Memory model'
    MEMORY_MODEL_DEFAULT: generic.lsh.LSHMemoryModel = Large (faster)
    MIN_NAME_LENGTH: unicode = u'Minimum data length'
    MIN_NAME_LENGTH_DEFAULT: int = 8
    NAME: unicode = u'Similar Data Match'
    SKIP_HOMOGENOUS_DATA: unicode = u'Skip Homogenous Data'
    SKIP_HOMOGENOUS_DATA_DEFAULT: bool = True



    def __init__(self): ...



    def createCorrelator(self, __a0: ghidra.framework.plugintool.ServiceProvider, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.address.AddressSetView, __a3: ghidra.program.model.listing.Program, __a4: ghidra.program.model.address.AddressSetView, __a5: ghidra.feature.vt.api.util.VTOptions) -> ghidra.feature.vt.api.main.VTProgramCorrelator: ...

    def createDefaultOptions(self) -> ghidra.feature.vt.api.util.VTOptions: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddressRestrictionPreference(self) -> ghidra.feature.vt.api.main.VTProgramCorrelatorAddressRestrictionPreference: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def getPriority(self) -> int: ...

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
    def description(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @property
    def priority(self) -> int: ...
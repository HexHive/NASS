from typing import List
import ghidra.feature.vt.api.impl
import ghidra.feature.vt.api.main
import ghidra.feature.vt.api.markuptype
import ghidra.feature.vt.api.util
import ghidra.feature.vt.gui.util
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang
import java.util


class PreCommentMarkupType(ghidra.feature.vt.api.markuptype.CommentMarkupType):
    INSTANCE: ghidra.feature.vt.api.markuptype.VTMarkupType = ghidra.feature.vt.api.markuptype.PreCommentMarkupType@40dfc457







    def applyMarkup(self, __a0: ghidra.feature.vt.api.main.VTMarkupItem, __a1: ghidra.framework.options.ToolOptions) -> bool: ...

    def conflictsWithOtherMarkup(self, __a0: ghidra.feature.vt.api.impl.MarkupItemImpl, __a1: java.util.Collection) -> bool: ...

    def convertOptionsToForceApplyOfMarkupItem(self, __a0: ghidra.feature.vt.api.main.VTMarkupItemApplyActionType, __a1: ghidra.framework.options.ToolOptions) -> ghidra.framework.options.Options: ...

    def createMarkupItems(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> List[object]: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self, __a0: ghidra.program.util.ProgramLocation, __a1: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address: ...

    def getApplyAction(self, __a0: ghidra.framework.options.ToolOptions) -> ghidra.feature.vt.api.main.VTMarkupItemApplyActionType: ...

    def getClass(self) -> java.lang.Class: ...

    def getCommentChoice(self, __a0: ghidra.framework.options.ToolOptions) -> ghidra.feature.vt.gui.util.VTMatchApplyChoices.CommentChoices: ...

    def getCurrentDestinationValue(self, __a0: ghidra.feature.vt.api.main.VTAssociation, __a1: ghidra.program.model.address.Address) -> ghidra.feature.vt.api.util.Stringable: ...

    def getDestinationFunction(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> ghidra.program.model.listing.Function: ...

    def getDestinationListing(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> ghidra.program.model.listing.Listing: ...

    def getDestinationLocation(self, __a0: ghidra.feature.vt.api.main.VTAssociation, __a1: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation: ...

    def getDestinationProgram(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> ghidra.program.model.listing.Program: ...

    def getDisplayName(self) -> unicode: ...

    def getOriginalDestinationValue(self, __a0: ghidra.feature.vt.api.main.VTAssociation, __a1: ghidra.program.model.address.Address) -> ghidra.feature.vt.api.util.Stringable: ...

    def getSourceFunction(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> ghidra.program.model.listing.Function: ...

    def getSourceListing(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> ghidra.program.model.listing.Listing: ...

    def getSourceLocation(self, __a0: ghidra.feature.vt.api.main.VTAssociation, __a1: ghidra.program.model.address.Address) -> ghidra.program.util.ProgramLocation: ...

    def getSourceProgram(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> ghidra.program.model.listing.Program: ...

    def getSourceValue(self, __a0: ghidra.feature.vt.api.main.VTAssociation, __a1: ghidra.program.model.address.Address) -> ghidra.feature.vt.api.util.Stringable: ...

    def hasSameSourceAndDestinationValues(self, __a0: ghidra.feature.vt.api.main.VTMarkupItem) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def supportsApplyAction(self, __a0: ghidra.feature.vt.api.main.VTMarkupItemApplyActionType) -> bool: ...

    def supportsAssociationType(self, __a0: ghidra.feature.vt.api.main.VTAssociationType) -> bool: ...

    def toString(self) -> unicode: ...

    def unapplyMarkup(self, __a0: ghidra.feature.vt.api.main.VTMarkupItem) -> None: ...

    def validateDestinationAddress(self, __a0: ghidra.feature.vt.api.main.VTAssociation, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


import ghidra.app.util.viewer.field
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.listing.CodeUnitFormatOptions
import ghidra.program.model.symbol
import java.lang
import javax.swing.event


class LabelCodeUnitFormat(ghidra.app.util.viewer.field.BrowserCodeUnitFormat):
    """
    A version of BrowserCodeUnitFormat that changes how labels are rendered in offcut 
     situations.
    """





    def __init__(self, fieldOptions: ghidra.framework.options.ToolOptions): ...



    def addChangeListener(self, listener: javax.swing.event.ChangeListener) -> None:
        """
        Add a change listener to the underlying format options.  When a format change
         occurs the listener may wish to trigger a refresh of of any formatted code units.
        @param listener change listener
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataValueRepresentation(self, data: ghidra.program.model.listing.Data) -> ghidra.program.model.listing.OperandRepresentationList:
        """
        Returns a formatted data value for the specified data unit. The return
         list will contain a single object which may be an instance of String,
         LabelString, Address, Scalar or Equate
        @param data data unit
        @return representation list containing a single object.
        """
        ...

    def getDataValueRepresentationString(self, data: ghidra.program.model.listing.Data) -> unicode:
        """
        Returns a formatted data value for the specified data unit.
        @param data data unit
        @return data value string
        """
        ...

    def getMnemonicRepresentation(self, cu: ghidra.program.model.listing.CodeUnit) -> unicode:
        """
        Returns a formatted code unit mnemonic
        @param cu code unit
        @return mnemonic representation
        """
        ...

    def getOffcutLabelString(self, offcutAddress: ghidra.program.model.address.Address, cu: ghidra.program.model.listing.CodeUnit) -> unicode: ...

    def getOperandRepresentationList(self, cu: ghidra.program.model.listing.CodeUnit, opIndex: int) -> ghidra.program.model.listing.OperandRepresentationList:
        """
        Returns a formatted list of operand objects for the specified code unit
         operand. In the case of Data opIndex=1, this will be a list containing a
         single String object (see getDataValueRepresentation(Data)). In the case
         of an Instruction, the list will contain a list of Objects, including any
         combination of Character, String, VariableOffset, Register, Address,
         Scalar, List, LabelString etc.. All objects returned must support the
         toString() method.
        @param cu code unit
        @param opIndex operand index
        @return list of representation objects or null for an unsupported
                 language.
        """
        ...

    def getOperandRepresentationString(self, cu: ghidra.program.model.listing.CodeUnit, opIndex: int) -> unicode:
        """
        Returns a formatted string representation of the specified code unit
         operand.
        @param cu code unit
        @param opIndex
        @return formatted code unit representation
        """
        ...

    def getReferenceRepresentationString(self, fromCodeUnit: ghidra.program.model.listing.CodeUnit, ref: ghidra.program.model.symbol.Reference) -> unicode:
        """
        Returns a marked-up representation of the reference destination.
        @param fromCodeUnit
        @param ref
        @return destination as a string or null if a suitable string could not be
                 produced.
        """
        ...

    @overload
    def getRepresentationString(self, cu: ghidra.program.model.listing.CodeUnit) -> unicode:
        """
        Returns a formatted string representation of the specified code unit,
         including mnemonic and operand(s) only.
        @param cu code unit
        @return formatted code unit representation
        """
        ...

    @overload
    def getRepresentationString(self, cu: ghidra.program.model.listing.CodeUnit, includeEOLcomment: bool) -> unicode:
        """
        Returns a formatted string representation of the specified code unit
         mnemonic and operand(s).
        @param cu code unit
        @param includeEOLcomment if true EOL comment will be appended to code
                    unit representation
        @return formatted code unit representation
        """
        ...

    def getShowBlockName(self) -> ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName:
        """
        Returns ShowBlockName setting
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener) -> None:
        """
        Remove an existing change listener from the underlying format options.
        @param listener change listener
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


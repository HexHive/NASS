from typing import List
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class MarkupSession(object):
    """
    State and methods needed for structure mapped objects to add markup, comments, labels, etc
     to a program.
    """





    def __init__(self, programContext: ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new markup session
        @param programContext program-level structure mapping context
        @param monitor allows user to cancel
        """
        ...



    def addReference(self, fieldContext: ghidra.app.util.bin.format.golang.structmapping.FieldContext, refDest: ghidra.program.model.address.Address) -> None:
        """
        Creates a reference from the specified field to the specified address.
        @param fieldContext field, is the source of the reference
        @param refDest destination address of the reference
        """
        ...

    @overload
    def appendComment(self, fieldContext: ghidra.app.util.bin.format.golang.structmapping.FieldContext, commentType: int, prefix: unicode, comment: unicode, sep: unicode) -> None:
        """
        Adds a comment to the specified field, appending to any previous values
         already there.  If the existing comment already contains the specified comment value,
         the operation is skipped.
        @param fieldContext the field
        @param commentType {@link CodeUnit#EOL_COMMENT}, {@link CodeUnit#PLATE_COMMENT},
         {@link CodeUnit#POST_COMMENT}, {@link CodeUnit#PRE_COMMENT}
        @param prefix String prefix to place in front of the comment string
        @param comment String value to append
        @param sep separator to use between existing comments (for example, "\n")
        @throws IOException if error adding comment
        """
        ...

    @overload
    def appendComment(self, structureContext: ghidra.app.util.bin.format.golang.structmapping.StructureContext, commentType: int, prefix: unicode, comment: unicode, sep: unicode) -> None:
        """
        Adds a comment to the specified structure, appending to any previous values
         already there.  If the existing comment already contains the specified comment value,
         the operation is skipped.
        @param structureContext the structure
        @param commentType {@link CodeUnit#EOL_COMMENT}, {@link CodeUnit#PLATE_COMMENT},
         {@link CodeUnit#POST_COMMENT}, {@link CodeUnit#PRE_COMMENT}
        @param prefix String prefix to place in front of the comment string
        @param comment String value to append
        @param sep separator to use between existing comments (for example, "\n")
        @throws IOException if error adding comment
        """
        ...

    def createFunctionIfMissing(self, name: unicode, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Creates a default function at the specified address.
        @param name name of the new function
        @param addr address of the new function
        @return {@link Function} that was created
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMappingContext(self) -> ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper:
        """
        Returns the program level mapping context
        @return {@link DataTypeMapper}
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the Ghidra program
        @return Ghidra {@link Program}
        """
        ...

    def hashCode(self) -> int: ...

    def labelAddress(self, addr: ghidra.program.model.address.Address, symbolName: unicode) -> None:
        """
        Places a label at the specified address.
        @param addr {@link Address}
        @param symbolName name
        @throws IOException if error
        """
        ...

    def labelStructure(self, obj: object, symbolName: unicode) -> None:
        """
        Places a label at the specified structure mapped object's address.
        @param <T> structure mapped object type
        @param obj structure mapped object
        @param symbolName name
        @throws IOException if error
        """
        ...

    def markup(self, obj: object, nested: bool) -> None:
        """
        Decorates the specified object's memory using the various structure mapping tags that 
         were applied the object's class definition.
         <p>
         The object can be a structure mapped object, or a collection, array or iterator of structure
         mapped objects.
        @param <T> structure mapped object type
        @param obj structure mapped object instance
        @param nested boolean flag, if true the specified object is contained inside another object
         who's data type has already been laid down in memory, removing the need for this object's
         data type to be applied to memory
        @throws IOException if error or cancelled
        @throws IllegalArgumentException if object instance is not a supported type
        """
        ...

    @overload
    def markupAddress(self, addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType) -> None:
        """
        Applies the specified {@link DataType} to the specified {@link Address}.
        @param addr location to place DataType
        @param dt {@link DataType}
        @throws IOException if error marking up address
        """
        ...

    @overload
    def markupAddress(self, addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType, length: int) -> None:
        """
        Applies the specified {@link DataType} to the specified {@link Address}.
        @param addr location to place DataType
        @param dt {@link DataType}
        @param length length of the data type instance, or -1 if the data type is fixed length
        @throws IOException if error marking up address
        """
        ...

    def markupAddressIfUndefined(self, addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType) -> None:
        """
        Applies the specified {@link DataType} to the specified {@link Address}.
        @param addr location to place DataType
        @param dt {@link DataType}
        @throws IOException if error marking up address
        """
        ...

    def markupArrayElementReferences(self, __a0: ghidra.program.model.address.Address, __a1: int, __a2: List[object]) -> None: ...

    def markupStructure(self, structureContext: ghidra.app.util.bin.format.golang.structmapping.StructureContext, nested: bool) -> None:
        """
        Decorates a structure mapped structure, and everything it contains.
        @param <T> structure mapped type
        @param structureContext {@link StructureContext}
        @param nested if true, it is assumed that the Ghidra data types have already been
         placed and only markup needs to be performed.
        @throws IOException if error marking up structure
        """
        ...

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
    def mappingContext(self) -> ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...
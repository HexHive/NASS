import docking.widgets.fieldpanel.support
import ghidra.app.util
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.proxy
import ghidra.framework.options
import ghidra.program.util
import java.awt
import java.lang


class AssignedVariableFieldFactory(ghidra.app.util.viewer.field.FieldFactory):
    """
    Generates Variable Assignment Fields (point of first-use).
    """

    FIELD_NAME: unicode = u'Var Assign'



    def __init__(self):
        """
        Default constructor.
        """
        ...



    def acceptsType(self, category: int, proxyObjectClass: java.lang.Class) -> bool: ...

    def displayOptionsChanged(self, options: ghidra.framework.options.Options, optionName: unicode, oldValue: object, newValue: object) -> None:
        """
        Notifications that the display options changed.
        @param options the Display Options object that changed.
        @param optionName the name of the property that changed.
        @param oldValue the old value of the property.
        @param newValue the new value of the property.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def fieldOptionsChanged(self, options: ghidra.framework.options.Options, optionName: unicode, oldValue: object, newValue: object) -> None:
        """
        Notifications that the field options changed.
        @param options the Field Options object that changed.
        @param optionName the name of the property that changed.
        @param oldValue the old value of the property.
        @param newValue the new value of the property.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getField(self, proxy: ghidra.app.util.viewer.proxy.ProxyObj, varWidth: int) -> ghidra.app.util.viewer.field.ListingField:
        """
        Returns the FactoryField for the given object at index index.
        @param varWidth the amount of variable width spacing for any fields
         before this one.
        @param proxy the object whose properties should be displayed.
        """
        ...

    def getFieldLocation(self, bf: ghidra.app.util.viewer.field.ListingField, index: long, fieldNum: int, programLoc: ghidra.program.util.ProgramLocation) -> docking.widgets.fieldpanel.support.FieldLocation: ...

    def getFieldModel(self) -> ghidra.app.util.viewer.format.FieldFormatModel:
        """
        Returns the FieldModel that this factory belongs to.
        @return the model.
        """
        ...

    def getFieldName(self) -> unicode:
        """
        Returns the Field name.
        @return the name.
        """
        ...

    def getFieldText(self) -> unicode:
        """
        Returns a description of the fields generated by this factory.
        @return the text.
        """
        ...

    def getMetrics(self) -> java.awt.FontMetrics:
        """
        Returns the font metrics used by this field factory
        @return the metrics.
        """
        ...

    def getProgramLocation(self, row: int, col: int, bf: ghidra.app.util.viewer.field.ListingField) -> ghidra.program.util.ProgramLocation: ...

    def getStartX(self) -> int:
        """
        Returns the starting x position for the fields generated by this factory.
        @return the start x.
        """
        ...

    def getWidth(self) -> int:
        """
        Returns the width of the fields generated by this factory.
        @return the width.
        """
        ...

    def hashCode(self) -> int: ...

    def isEnabled(self) -> bool:
        """
        Returns true if this FieldFactory is currently enabled to generate Fields.
        @return true if enabled.
        """
        ...

    def newInstance(self, formatModel: ghidra.app.util.viewer.format.FieldFormatModel, hsProvider: ghidra.app.util.ListingHighlightProvider, displayOptions: ghidra.framework.options.ToolOptions, fieldOptions: ghidra.framework.options.ToolOptions) -> ghidra.app.util.viewer.field.FieldFactory: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def servicesChanged(self) -> None:
        """
        Notification the services changed. Subclasses should override this method
         if they care about service changes.
        """
        ...

    def setEnabled(self, state: bool) -> None:
        """
        Turns on or off the generating of Fields by this FieldFactory.
        @param state if true, this factory will generate fields.
        """
        ...

    def setStartX(self, x: int) -> None:
        """
        Sets the starting x position for the fields generated by this factory.
        @param x the x position.
        """
        ...

    def setWidth(self, w: int) -> None:
        """
        Sets the width of the fields generated by this factory.
        @param w the width.
        """
        ...

    def supportsLocation(self, listingField: ghidra.app.util.viewer.field.ListingField, location: ghidra.program.util.ProgramLocation) -> bool:
        """
        Returns true if this given field represents the given location
        @param listingField the field
        @param location the location
        @return true if this given field represents the given location
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


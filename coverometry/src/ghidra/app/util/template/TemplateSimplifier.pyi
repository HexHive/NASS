import ghidra.framework.options
import ghidra.program.model.symbol
import java.lang


class TemplateSimplifier(object, ghidra.program.model.symbol.NameTransformer):
    """
    Class for simplify names with template data. This class can be used with tool options or
     as a stand alone configurable simplifier.
    """

    MAX_TEMPLATE_LENGTH_DESCRIPTION: unicode = u'Maximum number of characters to display in a template before truncating the name in the middle.'
    MAX_TEMPLATE_LENGTH_OPTION: unicode = u'Templates.Max Template Length'
    MIN_TEMPLATE_LENGTH_DESCRIPTION: unicode = u'Minumum size of template to be simplified'
    MIN_TEMPLATE_LENGTH_OPTION: unicode = u'Templates.Min Template Length'
    SIMPLIFY_TEMPLATES_OPTION: unicode = u'Templates.Simplify Templated Names'
    SIMPLY_TEMPLATES_DESCRIPTION: unicode = u'Determines whether to diplay templated names in a simplified form.'
    SUB_OPTION_NAME: unicode = u'Templates'
    TEMPLATE_NESTING_DEPTH_DESCRIPTION: unicode = u'Maximum template depth to display when simplify templated names.'
    TEMPLATE_NESTING_DEPTH_OPTION: unicode = u'Templates.Max Template Depth'



    @overload
    def __init__(self):
        """
        Constructor to use for a TemplateSimplifier that doesn't use values from ToolOptions
        """
        ...

    @overload
    def __init__(self, fieldOptions: ghidra.framework.options.ToolOptions):
        """
        Constructor to use for a TemplateSimplifier that operates using the current values in 
         the tool options
        @param fieldOptions the "Listing Field" options
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def fieldOptionsChanged(self, options: ghidra.framework.options.Options, optionName: unicode, oldValue: object, newValue: object) -> bool:
        """
        Notification that options have changed
        @param options the options object that has changed values
        @param optionName the name of the options that changed
        @param oldValue the old value for the option that changed
        @param newValue the new value for the option that changed
        @return true if the option that changed was a template simplification option
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getMaxTemplateLength(self) -> int:
        """
        Gets the maximum length that a template will display.
        @return the maximum length that a template will display
        """
        ...

    def getMinimumTemplateLength(self) -> int:
        """
        Returns the minimum length of a template string that will be simplified.
        @return the minimum length of a template string that will be simplified.
        """
        ...

    def getNestingDepth(self) -> int:
        """
        Returns the nesting depth for simplification
        @return the nesting depth for simplification
        """
        ...

    def hashCode(self) -> int: ...

    def isEnabled(self) -> bool:
        """
        Returns if this TemplateSimplifier is enabled.
        @return if this TemplateSimplifier is enabled
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def reloadFromOptions(self, fieldOptions: ghidra.framework.options.ToolOptions) -> None:
        """
        Reloads the current simplification settings from the given field options
        @param fieldOptions the options to retrieve the simplification settings.
        """
        ...

    def setEnabled(self, doSimplify: bool) -> None:
        """
        Sets if this TemplateSimplifier is enabled. If disabled, the {@link #simplify(String)} 
         method will return the input string.
        @param doSimplify true to do simplification, false to do nothing
        """
        ...

    def setMaxTemplateLength(self, maxLength: int) -> None:
        """
        Sets the maximum length do display the template portion. If, after any nesting,
         simplification, the resulting template string is longer that the max length, the middle
         portion will be replaced with "..." to reduce the template string to the given max length.
        @param maxLength the max length of a template to display
        """
        ...

    def setMinimumTemplateLength(self, minLength: int) -> None:
        """
        Sets the minimum length for a template string to be simplified. In other words, template
         strings less than this length will not be changed.
        @param minLength the minimum length to simplify
        """
        ...

    def setNestingDepth(self, depth: int) -> None:
        """
        Sets the template nesting depth to be simplified. A depth of 0 simplifies the entire 
         template portion of the name (everything in between {@code <>}). A depth of 1 leaves one 
         level of template information
        @param depth the nesting depth
        """
        ...

    def simplify(self, input: unicode) -> unicode:
        """
        Simplifies any template string in the given input base on the current simplification
         settings.
        @param input the input string to be simplified
        @return a simplified string
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def enabled(self) -> bool: ...

    @enabled.setter
    def enabled(self, value: bool) -> None: ...

    @property
    def maxTemplateLength(self) -> int: ...

    @maxTemplateLength.setter
    def maxTemplateLength(self, value: int) -> None: ...

    @property
    def minimumTemplateLength(self) -> int: ...

    @minimumTemplateLength.setter
    def minimumTemplateLength(self, value: int) -> None: ...

    @property
    def nestingDepth(self) -> int: ...

    @nestingDepth.setter
    def nestingDepth(self, value: int) -> None: ...
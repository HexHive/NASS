import java.awt
import java.lang


class ColorUtils(object):
    COMPARATOR: java.util.Comparator
    HUE_BLUE: float = 0.6666666865348816
    HUE_GREEN: float = 0.3333333432674408
    HUE_LIME: float = 0.25
    HUE_ORANGE: float = 0.0833333358168602
    HUE_PINE: float = 0.4166666567325592
    HUE_PINK: float = 0.9166666865348816
    HUE_PURPLE: float = 0.8333333134651184
    HUE_RED: float = 0.0
    HUE_ROYAL: float = 0.75
    HUE_SAPPHIRE: float = 0.5833333134651184
    HUE_TURQUISE: float = 0.5
    HUE_YELLOW: float = 0.1666666716337204




    class ColorBlender(object):




        def __init__(self): ...



        def add(self, __a0: java.awt.Color) -> None: ...

        def clear(self) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getColor(self, __a0: java.awt.Color) -> java.awt.Color: ...

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



    def __init__(self): ...



    @staticmethod
    def addColors(primary: java.awt.Color, secondary: java.awt.Color) -> java.awt.Color:
        """
        Combines colors in a way the makes them stand out from each other more than just averaging
         them together. Basically if the colors are bright, the result is a darker value than the
         primary, adjusted based on the values in the secondary. If the colors are dark, then the
         result is a brighter version of the primary color adjusted based on values in the secondary
         color.
        @param primary the primary color to be tweaked
        @param secondary the color to used to determine the amount to tweak the red,green,blue values
        @return a new color that is a combination of the two colors
        """
        ...

    @staticmethod
    def average(color1: java.awt.Color, color2: java.awt.Color) -> java.awt.Color:
        """
        Creates a new color by averaging the red, green, blue, and alpha values from the given
         colors.
        @param color1 the first color to average
        @param color2 the second color to average
        @return a new color that is the average of the two given colors
        """
        ...

    @staticmethod
    def blend(c1: java.awt.Color, c2: java.awt.Color, ratio: float) -> java.awt.Color:
        """
        Takes the first color, blending into it the second color, using the given ratio. A lower
         ratio (say .1f) signals to use very little of the first color; a larger ratio signals to use
         more of the first color.
        @param c1 the first color
        @param c2 the second color
        @param ratio the amount of the first color to include in the final output
        @return the new color
        """
        ...

    @staticmethod
    def contrastForegroundColor(color: java.awt.Color) -> java.awt.Color:
        """
        A method to produce a color (either black or white) that contrasts with the given color. This
         is useful for finding a readable foreground color for a given background.
        @param color the color for which to find a contrast.
        @return the contrasting color.
        """
        ...

    @overload
    @staticmethod
    def deriveBackground(background: java.awt.Color, hue: float) -> java.awt.Color: ...

    @overload
    @staticmethod
    def deriveBackground(src: java.awt.Color, hue: float, sfact: float, bfact: float) -> java.awt.Color: ...

    @overload
    @staticmethod
    def deriveForeground(bg: java.awt.Color, hue: float) -> java.awt.Color: ...

    @overload
    @staticmethod
    def deriveForeground(bg: java.awt.Color, hue: float, brt: float) -> java.awt.Color: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    @staticmethod
    def getColor(rgba: int) -> java.awt.Color:
        """
        Return the color object given a rgba value that includes the desired alpha value.
        @param rgba value where bits 24-31 are alpha, 16-23 are red, 8-15 are green, 0-7 are
         blue
        @return the color object given a rgba value that includes the desired alpha value
        """
        ...

    @overload
    @staticmethod
    def getColor(red: int, green: int, blue: int) -> java.awt.Color:
        """
        Return an opaque color object given for the given red, green, and blue values.
        @param red the red value (0 - 255)
        @param green the green value (0 - 255)
        @param blue the blue value (0 - 255)
        @return the color object for the given values
        """
        ...

    @overload
    @staticmethod
    def getColor(red: int, green: int, blue: int, alpha: int) -> java.awt.Color:
        """
        Return the color object given for the given red, green, blue, and alpha values.
        @param red the red value (0 - 255)
        @param green the green value (0 - 255)
        @param blue the blue value (0 - 255)
        @param alpha the alpha (transparency) value (0 - 255) with 0 being fully transparent and 255 
         being fully opaque opaque
        @return the color object for the given values
        """
        ...

    @staticmethod
    def getOpaqueColor(rgb: int) -> java.awt.Color:
        """
        Returns an opaque color with the given rgb value. The resulting color will have an alpha
         value of 0xff.
        @param rgb the value where bits 16-23 are red, 8-15 are green, 0-7 are blue. Bits 24-31 will
         be set to 0xff.
        @return an opaque color with the given rgb value
        """
        ...

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

    @staticmethod
    def withAlpha(c: java.awt.Color, alpha: int) -> java.awt.Color:
        """
        Returns a new color that is comprised of the given color's rgb value and the given alpha
         value.
        @param c the color
        @param alpha the alpha
        @return the new color
        """
        ...


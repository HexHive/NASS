import java.awt
import java.lang


class WebColors(object):
    """
    Class for web color support. This class defines many of the colors used by html. This class
     includes methods for converting a color to a string (name or hex value) and for converting
     those strings back to a color.
 
     Usage Note: Java's HTML rendering engine supports colors in hex form ('#aabb11').  Also, the
     engine supports many web color names ('silver').  However, not all web color names defined in
     this file are supported.  Thus, when specifying HTML colors, do not rely on these web color
     names.
    """

    ALICE_BLUE: java.awt.Color = java.awt.Color[r=240,g=248,b=255]
    ANTIQUE_WHITE: java.awt.Color = java.awt.Color[r=250,g=235,b=215]
    AQUA: java.awt.Color = java.awt.Color[r=0,g=255,b=255]
    AQUAMARINE: java.awt.Color = java.awt.Color[r=127,g=255,b=212]
    AZURE: java.awt.Color = java.awt.Color[r=240,g=255,b=255]
    BEIGE: java.awt.Color = java.awt.Color[r=245,g=245,b=220]
    BISQUE: java.awt.Color = java.awt.Color[r=255,g=228,b=196]
    BLACK: java.awt.Color = java.awt.Color[r=0,g=0,b=0]
    BLANCHED_ALMOND: java.awt.Color = java.awt.Color[r=255,g=235,b=205]
    BLUE: java.awt.Color = java.awt.Color[r=0,g=0,b=255]
    BLUE_VIOLET: java.awt.Color = java.awt.Color[r=138,g=43,b=226]
    BROWN: java.awt.Color = java.awt.Color[r=165,g=42,b=42]
    BURLYWOOD: java.awt.Color = java.awt.Color[r=222,g=184,b=135]
    CADET_BLUE: java.awt.Color = java.awt.Color[r=95,g=158,b=160]
    CHARTREUSE: java.awt.Color = java.awt.Color[r=127,g=255,b=0]
    CHOCOLATE: java.awt.Color = java.awt.Color[r=210,g=105,b=30]
    CORAL: java.awt.Color = java.awt.Color[r=255,g=127,b=80]
    CORNFLOWER_BLUE: java.awt.Color = java.awt.Color[r=100,g=149,b=237]
    CORNSILK: java.awt.Color = java.awt.Color[r=255,g=248,b=220]
    CRIMSON: java.awt.Color = java.awt.Color[r=220,g=20,b=60]
    CYAN: java.awt.Color = java.awt.Color[r=0,g=255,b=255]
    DARK_BLUE: java.awt.Color = java.awt.Color[r=0,g=0,b=139]
    DARK_CYAN: java.awt.Color = java.awt.Color[r=0,g=139,b=139]
    DARK_GOLDENROD: java.awt.Color = java.awt.Color[r=184,g=134,b=11]
    DARK_GRAY: java.awt.Color = java.awt.Color[r=169,g=169,b=169]
    DARK_GREEN: java.awt.Color = java.awt.Color[r=0,g=100,b=0]
    DARK_KHAKI: java.awt.Color = java.awt.Color[r=189,g=183,b=107]
    DARK_MAGENTA: java.awt.Color = java.awt.Color[r=139,g=0,b=139]
    DARK_OLIVE_GREEN: java.awt.Color = java.awt.Color[r=85,g=107,b=47]
    DARK_ORANGE: java.awt.Color = java.awt.Color[r=255,g=140,b=0]
    DARK_ORCHID: java.awt.Color = java.awt.Color[r=153,g=50,b=204]
    DARK_RED: java.awt.Color = java.awt.Color[r=139,g=0,b=0]
    DARK_SALMON: java.awt.Color = java.awt.Color[r=233,g=150,b=122]
    DARK_SEA_GREEN: java.awt.Color = java.awt.Color[r=143,g=188,b=143]
    DARK_SLATE_BLUE: java.awt.Color = java.awt.Color[r=72,g=61,b=139]
    DARK_SLATE_GRAY: java.awt.Color = java.awt.Color[r=47,g=79,b=79]
    DARK_TURQUOSE: java.awt.Color = java.awt.Color[r=0,g=206,b=209]
    DARK_VIOLET: java.awt.Color = java.awt.Color[r=148,g=0,b=211]
    DEEP_PINK: java.awt.Color = java.awt.Color[r=255,g=20,b=147]
    DEEP_SKY_BLUE: java.awt.Color = java.awt.Color[r=0,g=191,b=255]
    DIM_GRAY: java.awt.Color = java.awt.Color[r=105,g=105,b=105]
    DOGER_BLUE: java.awt.Color = java.awt.Color[r=30,g=144,b=255]
    FIRE_BRICK: java.awt.Color = java.awt.Color[r=178,g=34,b=34]
    FLORAL_WHITE: java.awt.Color = java.awt.Color[r=255,g=250,b=240]
    FOREST_GREEN: java.awt.Color = java.awt.Color[r=34,g=139,b=34]
    FUCHSIA: java.awt.Color = java.awt.Color[r=255,g=0,b=255]
    GAINSBORO: java.awt.Color = java.awt.Color[r=220,g=220,b=220]
    GHOST_WHITE: java.awt.Color = java.awt.Color[r=248,g=248,b=255]
    GOLD: java.awt.Color = java.awt.Color[r=255,g=215,b=0]
    GOLDEN_ROD: java.awt.Color = java.awt.Color[r=218,g=165,b=32]
    GRAY: java.awt.Color = java.awt.Color[r=128,g=128,b=128]
    GREEN: java.awt.Color = java.awt.Color[r=0,g=128,b=0]
    GREEN_YELLOW: java.awt.Color = java.awt.Color[r=173,g=255,b=47]
    HONEY_DEW: java.awt.Color = java.awt.Color[r=240,g=255,b=240]
    HOT_PINK: java.awt.Color = java.awt.Color[r=255,g=105,b=180]
    INDIAN_RED: java.awt.Color = java.awt.Color[r=205,g=92,b=92]
    INDIGO: java.awt.Color = java.awt.Color[r=75,g=0,b=130]
    IVORY: java.awt.Color = java.awt.Color[r=255,g=255,b=240]
    KHAKE: java.awt.Color = java.awt.Color[r=240,g=230,b=140]
    LAVENDER: java.awt.Color = java.awt.Color[r=230,g=230,b=250]
    LAVENDER_BLUSH: java.awt.Color = java.awt.Color[r=255,g=240,b=245]
    LAWN_GREEN: java.awt.Color = java.awt.Color[r=124,g=252,b=0]
    LEMON_CHIFFON: java.awt.Color = java.awt.Color[r=255,g=250,b=205]
    LIGHT_BLUE: java.awt.Color = java.awt.Color[r=173,g=216,b=230]
    LIGHT_CORAL: java.awt.Color = java.awt.Color[r=240,g=128,b=128]
    LIGHT_CYAN: java.awt.Color = java.awt.Color[r=224,g=255,b=255]
    LIGHT_GOLDENROD: java.awt.Color = java.awt.Color[r=250,g=250,b=210]
    LIGHT_GRAY: java.awt.Color = java.awt.Color[r=211,g=211,b=211]
    LIGHT_GREEN: java.awt.Color = java.awt.Color[r=144,g=238,b=144]
    LIGHT_PINK: java.awt.Color = java.awt.Color[r=255,g=182,b=193]
    LIGHT_SALMON: java.awt.Color = java.awt.Color[r=255,g=160,b=122]
    LIGHT_SEA_GREEN: java.awt.Color = java.awt.Color[r=32,g=178,b=170]
    LIGHT_SKY_BLUE: java.awt.Color = java.awt.Color[r=135,g=206,b=250]
    LIGHT_SLATE_GRAY: java.awt.Color = java.awt.Color[r=119,g=136,b=153]
    LIGHT_STEEL_BLUE: java.awt.Color = java.awt.Color[r=176,g=196,b=222]
    LIGHT_YELLOW: java.awt.Color = java.awt.Color[r=255,g=255,b=224]
    LIME: java.awt.Color = java.awt.Color[r=0,g=255,b=0]
    LIME_GREEN: java.awt.Color = java.awt.Color[r=50,g=205,b=50]
    LINEN: java.awt.Color = java.awt.Color[r=250,g=240,b=230]
    MAGENTA: java.awt.Color = java.awt.Color[r=255,g=0,b=255]
    MAROON: java.awt.Color = java.awt.Color[r=128,g=0,b=0]
    MEDIUM_BLUE: java.awt.Color = java.awt.Color[r=0,g=0,b=205]
    MEDIUM_ORCHID: java.awt.Color = java.awt.Color[r=186,g=85,b=211]
    MEDIUM_PURPLE: java.awt.Color = java.awt.Color[r=147,g=112,b=219]
    MEDIUM_SEA_GREEN: java.awt.Color = java.awt.Color[r=60,g=179,b=113]
    MEDIUM_SLATE_BLUE: java.awt.Color = java.awt.Color[r=123,g=104,b=238]
    MEDIUM_SPRING_GREEN: java.awt.Color = java.awt.Color[r=0,g=250,b=154]
    MEDIUM_TURQOISE: java.awt.Color = java.awt.Color[r=72,g=209,b=204]
    MEDIUM_VIOLET_RED: java.awt.Color = java.awt.Color[r=199,g=21,b=133]
    MEDUM_AQUA_MARINE: java.awt.Color = java.awt.Color[r=102,g=205,b=170]
    MIDNIGHT_BLUE: java.awt.Color = java.awt.Color[r=25,g=25,b=112]
    MINT_CREAM: java.awt.Color = java.awt.Color[r=245,g=255,b=250]
    MISTY_ROSE: java.awt.Color = java.awt.Color[r=255,g=228,b=225]
    MOCCASIN: java.awt.Color = java.awt.Color[r=255,g=228,b=181]
    NAVAJO_WHITE: java.awt.Color = java.awt.Color[r=255,g=222,b=173]
    NAVY: java.awt.Color = java.awt.Color[r=0,g=0,b=128]
    OLDLACE: java.awt.Color = java.awt.Color[r=253,g=245,b=230]
    OLIVE: java.awt.Color = java.awt.Color[r=128,g=128,b=0]
    OLIVE_DRAB: java.awt.Color = java.awt.Color[r=107,g=142,b=35]
    ORANGE: java.awt.Color = java.awt.Color[r=255,g=165,b=0]
    ORANGE_RED: java.awt.Color = java.awt.Color[r=255,g=69,b=0]
    ORCHID: java.awt.Color = java.awt.Color[r=218,g=112,b=214]
    PALE_GOLDENROD: java.awt.Color = java.awt.Color[r=238,g=232,b=170]
    PALE_GREEN: java.awt.Color = java.awt.Color[r=152,g=251,b=152]
    PALE_TURQUOISE: java.awt.Color = java.awt.Color[r=175,g=238,b=238]
    PALE_VIOLET_RED: java.awt.Color = java.awt.Color[r=219,g=112,b=147]
    PAPAYA_WHIP: java.awt.Color = java.awt.Color[r=255,g=239,b=213]
    PEACH_PUFF: java.awt.Color = java.awt.Color[r=255,g=218,b=185]
    PERU: java.awt.Color = java.awt.Color[r=205,g=133,b=63]
    PINK: java.awt.Color = java.awt.Color[r=255,g=192,b=203]
    PLUM: java.awt.Color = java.awt.Color[r=221,g=160,b=221]
    POWDER_BLUE: java.awt.Color = java.awt.Color[r=176,g=224,b=230]
    PURPLE: java.awt.Color = java.awt.Color[r=128,g=0,b=128]
    REBECCA_PURPLE: java.awt.Color = java.awt.Color[r=102,g=51,b=153]
    RED: java.awt.Color = java.awt.Color[r=255,g=0,b=0]
    ROSY_BROWN: java.awt.Color = java.awt.Color[r=188,g=143,b=143]
    ROYAL_BLUE: java.awt.Color = java.awt.Color[r=65,g=105,b=225]
    SADDLE_BROWN: java.awt.Color = java.awt.Color[r=139,g=69,b=19]
    SALMON: java.awt.Color = java.awt.Color[r=250,g=128,b=114]
    SANDY_BROWN: java.awt.Color = java.awt.Color[r=244,g=164,b=96]
    SEASHELL: java.awt.Color = java.awt.Color[r=255,g=245,b=238]
    SEA_GREEN: java.awt.Color = java.awt.Color[r=46,g=139,b=87]
    SIENNA: java.awt.Color = java.awt.Color[r=160,g=82,b=45]
    SILVER: java.awt.Color = java.awt.Color[r=192,g=192,b=192]
    SLATE_BLUE: java.awt.Color = java.awt.Color[r=106,g=90,b=205]
    SLATE_GRAY: java.awt.Color = java.awt.Color[r=112,g=128,b=144]
    SNOW: java.awt.Color = java.awt.Color[r=255,g=250,b=250]
    SPRING_GREEN: java.awt.Color = java.awt.Color[r=0,g=255,b=127]
    STEEL_BLUE: java.awt.Color = java.awt.Color[r=70,g=130,b=180]
    SYY_BLUE: java.awt.Color = java.awt.Color[r=135,g=206,b=235]
    TAN: java.awt.Color = java.awt.Color[r=210,g=180,b=140]
    TEAL: java.awt.Color = java.awt.Color[r=0,g=128,b=128]
    THISTLE: java.awt.Color = java.awt.Color[r=216,g=191,b=216]
    TOMATO: java.awt.Color = java.awt.Color[r=255,g=99,b=71]
    TURQUOISE: java.awt.Color = java.awt.Color[r=64,g=224,b=208]
    VIOLET: java.awt.Color = java.awt.Color[r=238,g=130,b=238]
    WHEAT: java.awt.Color = java.awt.Color[r=245,g=222,b=179]
    WHITE: java.awt.Color = java.awt.Color[r=255,g=255,b=255]
    WHITE_SMOKE: java.awt.Color = java.awt.Color[r=245,g=245,b=245]
    YELLOW: java.awt.Color = java.awt.Color[r=255,g=255,b=0]
    YELLOW_GREEN: java.awt.Color = java.awt.Color[r=154,g=205,b=50]







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getColor(colorString: unicode) -> java.awt.Color:
        """
        Attempts to convert the given string into a color in a most flexible manner. It first checks
         if the given string matches the name of a known web color as defined above. If so it
         returns that color. Otherwise it tries to parse the string in any one of the following
         formats:
         <pre>
         #rrggbb
         #rrggbbaa
         0xrrggbb
         0xrrggbbaa
         rgb(red, green, blue)
         rgba(red, green, alpha)
         </pre>
         In the hex digit formats, the hex digits "rr", "gg", "bb", "aa" represent the values for red,
         green, blue, and alpha, respectively. In the "rgb" and "rgba" formats the red, green, and
         blue values are all integers between 0-255, while the alpha value is a float value from 0.0 to
         1.0.
         <BR><BR>
        @param colorString the color name
        @return a color for the given string or null
        """
        ...

    @staticmethod
    def getColorOrDefault(value: unicode, defaultColor: java.awt.Color) -> java.awt.Color:
        """
        Tries to find a color for the given String value. The String value can either be
         a hex string (see {@link Color#decode(String)}) or a web color name as defined
         above
        @param value the string value to interpret as a color
        @param defaultColor a default color to return if the string can't be converted to a color
        @return a color for the given string value or the default color if the string can't be translated
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def toColorName(color: java.awt.Color) -> unicode: ...

    @staticmethod
    def toHexString(color: java.awt.Color) -> unicode:
        """
        Returns the hex value string for the given color
        @param color the color
        @return the string
        """
        ...

    @staticmethod
    def toRgbString(color: java.awt.Color) -> unicode:
        """
        Returns the rgb value string for the given color
        @param color the color
        @return the string
        """
        ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def toString(color: java.awt.Color) -> unicode:
        """
        Converts a color to a string value. If there is a defined color for the given color value,
         the color name will be returned. Otherwise, it will return a hex string for the color as
         follows. If the color has an non-opaque alpha value, it will be of the form #rrggbb. If
         it has an alpha value,then the format will be #rrggbbaa.
        @param color the color to convert to a string.
        @return the string representation for the given color.
        """
        ...

    @overload
    @staticmethod
    def toString(color: java.awt.Color, useNameIfPossible: bool) -> unicode:
        """
        Converts a color to a string value.  If the color is a WebColor and the useNameIfPossible
         is true, the name of the color will be returned. OOtherwise, it will return a hex string for the color as
         follows. If the color has an non-opaque alpha value, it will be of the form #rrggbb. If
         it has an alpha value ,then the format will be #rrggbbaa.
        @param color the color to convert to a string.
        @param useNameIfPossible if true, the name of the color will be returned if the color is
         a WebColor
        @return the string representation for the given color.
        """
        ...

    @staticmethod
    def toWebColorName(color: java.awt.Color) -> unicode:
        """
        Returns the WebColor name for the given color. Returns null if the color is not a WebColor
        @param color the color to lookup a WebColor name.
        @return the WebColor name for the given color. Returns null if the color is not a WebColor
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


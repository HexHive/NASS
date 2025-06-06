import java.lang
import javax.swing


class DataImage(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getImageFileType(self) -> unicode:
        """
        Returns the type of the underlying image data, suitable for
         {@link ImageIO#write(java.awt.image.RenderedImage, String, java.io.File)}'s formatName
         parameter.
        @return String image format type, ie. "png", "gif", "bmp"
        """
        ...

    def getImageIcon(self) -> javax.swing.ImageIcon:
        """
        Return image icon
        @return image object
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDescription(self, description: unicode) -> None:
        """
        Set string description (returned by toString)
        @param description
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
    def description(self) -> None: ...  # No getter available.

    @description.setter
    def description(self, value: unicode) -> None: ...

    @property
    def imageFileType(self) -> unicode: ...

    @property
    def imageIcon(self) -> javax.swing.ImageIcon: ...
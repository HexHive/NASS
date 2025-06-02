import generic.theme
import java.lang
import javax.swing.plaf


class LookAndFeelUtils(object):
    """
    A utility class to manage LookAndFeel (LaF) settings.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getLookAndFeelType() -> generic.theme.LafType:
        """
        Returns the {@link LafType} for the currently active {@link LookAndFeel}
        @return the {@link LafType} for the currently active {@link LookAndFeel}
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def installGlobalOverrides() -> None:
        """
        Loads settings from {@link Preferences}.
        """
        ...

    @staticmethod
    def isUsingAquaUI(UI: javax.swing.plaf.ComponentUI) -> bool:
        """
        Returns true if the given UI object is using the Aqua Look and Feel.
        @param UI the UI to examine.
        @return true if the UI is using Aqua
        """
        ...

    @staticmethod
    def isUsingNimbusUI() -> bool:
        """
        Returns true if 'Nimbus' is the current Look and Feel
        @return true if 'Nimbus' is the current Look and Feel
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def performPlatformSpecificFixups() -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


import java.lang
import java.net


class ProjectViewListener(object):
    """
     provides a listener interface for tracking project views added
     and removed from the associated project. 
 
     NOTE: notification callbacks are not guarenteed to occur within the swing thread.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def viewedProjectAdded(self, projectView: java.net.URL) -> None:
        """
        Provides notification that a read-only viewed project has been added which is intended to
         be visible.  Notification for hidden viewed projects will not be provided.
        @param projectView project view URL
        """
        ...

    def viewedProjectRemoved(self, projectView: java.net.URL) -> None:
        """
        Provides notification that a viewed project is being removed from the project.
         Notification for hidden viewed project removal will not be provided.
        @param projectView project view URL
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


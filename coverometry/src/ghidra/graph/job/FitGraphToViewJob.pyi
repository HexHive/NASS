import ghidra.graph.job
import java.lang


class FitGraphToViewJob(object, ghidra.graph.job.GraphJob):
    """
    A job to scale one or more viewers such that the contained graph will fit entirely inside the
     viewing area.
    """





    @overload
    def __init__(self, __a0: List[edu.uci.ics.jung.visualization.VisualizationServer]): ...

    @overload
    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer, onlyResizeWhenTooBig: bool): ...



    def canShortcut(self) -> bool: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def execute(self, listener: ghidra.graph.job.GraphJobListener) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isFinished(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def shortcut(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def finished(self) -> bool: ...
from typing import List
import edu.uci.ics.jung.visualization.picking
import ghidra.graph.viewer.event.picking
import java.awt.event
import java.lang
import java.util


class GPickedState(object, edu.uci.ics.jung.visualization.picking.PickedState):
    """
    This picked-state is a wrapper for PickedState that allows us to broadcast events
     with the trigger of that event.
    """





    def __init__(self, pickedState: edu.uci.ics.jung.visualization.picking.MultiPickedState): ...



    def addItemListener(self, l: java.awt.event.ItemListener) -> None: ...

    def addPickingListener(self, pickListener: ghidra.graph.viewer.event.picking.PickListener) -> None: ...

    def clear(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPicked(self) -> java.util.Set: ...

    def getSelectedObjects(self) -> List[object]: ...

    def hashCode(self) -> int: ...

    def isPicked(self, __a0: object) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def pick(self, __a0: object, __a1: bool) -> bool: ...

    def pickToActivate(self, __a0: object) -> None: ...

    @overload
    def pickToSync(self, __a0: object) -> None: ...

    @overload
    def pickToSync(self, __a0: object, __a1: bool) -> None: ...

    def removeItemListener(self, l: java.awt.event.ItemListener) -> None: ...

    def removePickingListener(self, pickListener: ghidra.graph.viewer.event.picking.PickListener) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def picked(self) -> java.util.Set: ...

    @property
    def selectedObjects(self) -> List[object]: ...
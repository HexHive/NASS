import docking.widgets.fieldpanel
import ghidra.app.decompiler
import ghidra.app.decompiler.component.margin
import ghidra.program.model.listing
import java.awt
import java.lang


class DecompilerMarginProvider(object):
    """
    A provider of a margin Swing component
 
 
     To add a margin to the decompiler, a client must implement this interface to provide the
     component that is actually added to the UI. For a reference implementation, see
     LineNumberDecompilerMarginProvider.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> java.awt.Component:
        """
        Get the Swing component implementing the actual margin, often {@code this}
        @return the component
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setOptions(self, options: ghidra.app.decompiler.DecompileOptions) -> None:
        """
        Set the options for the margin
 
         <p>
         This is called at least once when the provider is added to the margin service. See
         {@link DecompilerMarginService#addMarginProvider(DecompilerMarginProvider)}. It subsequently
         called whenever a decompiler option changes. To receive other options, the provider will need
         to listen using its own mechanism.
 
         <p>
         A call to this method should cause the component to be repainted. Implementors may choose to
         repaint only when certain options change.
        """
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program, model: docking.widgets.fieldpanel.LayoutModel, pixmap: ghidra.app.decompiler.component.margin.LayoutPixelIndexMap) -> None:
        """
        Called whenever the program, function, or layout changes
 
         <p>
         The implementation should keep a reference at least to the {@code model} and the
         {@code pixmap} for later use during painting. The model provides access to the lines of
         decompiler C code. Each layout corresponds to a single line of C code. For example, the first
         line of code is rendered by the layout at index 0. The tenth is rendered by the layout at
         index 9. Rarely, a line may be wrapped by the renderer, leading to a non-uniform layout. The
         {@code pixmap} can map from a pixel's vertical position to the layout index at the same
         position in the main panel. It accounts for scrolling an non-uniformity. It is safe to assume
         the layouts render contiguous lines of C code. The recommended strategy for painting is thus:
 
         <ol>
         <li>Compute the visible part of the margin needing repainting. See
         {@link JComponent#getVisibleRect()}</li>
         <li>Compute the layout indices for the vertical bounds of that part. See
         {@link LayoutPixelIndexMap#getIndex(int)}</li>
         <li>Iterate over the layouts within those bounds, inclusively.</li>
         <li>Compute the vertical position of each layout and paint something appropriate for its
         corresponding line. See {@link LayoutPixelIndexMap#getPixel(BigInteger)}</li>
         </ol>
 
         <p>
         A call to this method should cause the component to be repainted.
        @param program the program for the current function
        @param model the line/token model
        @param pixmap a map from pixels' y coordinates to layout index, i.e, line number
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
    def component(self) -> java.awt.Component: ...

    @property
    def options(self) -> None: ...  # No getter available.

    @options.setter
    def options(self, value: ghidra.app.decompiler.DecompileOptions) -> None: ...
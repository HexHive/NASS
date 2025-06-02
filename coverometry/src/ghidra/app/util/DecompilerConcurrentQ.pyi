from typing import Iterator
import java.lang
import java.util
import java.util.function


class DecompilerConcurrentQ(object):
    """
    A class to perform some of the boilerplate setup of the ConcurrentQ that is shared
     amongst clients that perform decompilation in parallel.

     This class can be used in a blocking or non-blocking fashion.

 
     		For blocking usage, call
     		one of the  methods to put items in the queue and then call
     		#waitForResults().
     		For non-blocking usage, simply call
     		#process(Iterator, Consumer), passing the consumer of the results.
 
 
    """





    @overload
    def __init__(self, callback: generic.concurrent.QCallback, monitor: ghidra.util.task.TaskMonitor): ...

    @overload
    def __init__(self, callback: generic.concurrent.QCallback, threadPoolName: unicode, monitor: ghidra.util.task.TaskMonitor): ...

    @overload
    def __init__(self, callback: generic.concurrent.QCallback, pool: generic.concurrent.GThreadPool, collectResults: bool, monitor: ghidra.util.task.TaskMonitor): ...



    def add(self, __a0: object) -> None: ...

    @overload
    def addAll(self, collection: java.util.Collection) -> None: ...

    @overload
    def addAll(self, iterator: Iterator[int]) -> None: ...

    @overload
    def dispose(self) -> None: ...

    @overload
    def dispose(self, timeoutSeconds: long) -> None:
        """
        Calls dispose on the queue being processed.  Further, the call will block for up to
         <tt>timeoutSeconds</tt> while waiting for the queue to finish processing.
        @param timeoutSeconds the number of seconds to wait for the disposed queue to finish
                processing
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def process(self, functions: Iterator[int], consumer: java.util.function.Consumer) -> None:
        """
        Adds all items to the queue for processing.  The results will be passed to the given consumer
         as they are produced.
        @param functions the functions to process
        @param consumer the results consumer
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def waitForResults(self) -> java.util.Collection:
        """
        Waits for all results to be delivered.  The client is responsible for processing the
         results and handling any exceptions that may have occurred.
        @return all results
        @throws InterruptedException if interrupted while waiting
        """
        ...

    def waitUntilDone(self) -> None:
        """
        Waits for all work to finish. Any exception encountered will trigger all processing to
         stop.  If you wish for the work to continue despite exceptions, then use
         {@link #waitForResults()}.
        @throws InterruptedException if interrupted while waiting
        @throws Exception any exception that is encountered while processing items.
        """
        ...


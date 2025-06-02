import ghidra.async
import ghidra.async.loop
import ghidra.async.seq
import java.lang
import java.nio.channels
import java.util
import java.util.concurrent
import java.util.function


class AsyncUtils(object):
    CLEANER: java.lang.ref.Cleaner = java.lang.ref.Cleaner@79df8ccf
    FRAMEWORK_EXECUTOR: java.util.concurrent.ExecutorService = java.util.concurrent.ForkJoinPool@1f40e0a5[Running, parallelism = 2, size = 0, active = 0, running = 0, steals = 0, tasks = 0, submissions = 0]
    NIL: java.util.concurrent.CompletableFuture = java.util.concurrent.CompletableFuture@4ab3b6ce[Completed normally]
    SWING_EXECUTOR: java.util.concurrent.ExecutorService = ghidra.async.SwingExecutorService$1@57d27593




    class TakesCompletionHandlerArity2(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def launch(self, __a0: object, __a1: object, __a2: object, __a3: java.nio.channels.CompletionHandler) -> None: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class TakesCompletionHandlerArity1(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def launch(self, __a0: object, __a1: object, __a2: java.nio.channels.CompletionHandler) -> None: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class TakesCompletionHandlerArity0(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def launch(self, __a0: object, __a1: java.nio.channels.CompletionHandler) -> None: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class TakesCompletionHandlerArity4(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def launch(self, __a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: java.nio.channels.CompletionHandler) -> None: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class TakesCompletionHandlerArity3(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def launch(self, __a0: object, __a1: object, __a2: object, __a3: object, __a4: java.nio.channels.CompletionHandler) -> None: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class FutureCompletionHandler(object, java.nio.channels.CompletionHandler):




        def __init__(self): ...



        def completed(self, __a0: object, __a1: object) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def failed(self, __a0: java.lang.Throwable, __a1: object) -> None: ...

        def getClass(self) -> java.lang.Class: ...

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






    class TemperamentalRunnable(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def run(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class TemperamentalSupplier(object):








        def equals(self, __a0: object) -> bool: ...

        def get(self) -> object: ...

        def getClass(self) -> java.lang.Class: ...

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







    @overload
    @staticmethod
    def completable(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.AsyncUtils.TakesCompletionHandlerArity0) -> java.util.concurrent.CompletableFuture: ...

    @overload
    @staticmethod
    def completable(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.AsyncUtils.TakesCompletionHandlerArity1, __a2: object) -> java.util.concurrent.CompletableFuture: ...

    @overload
    @staticmethod
    def completable(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.AsyncUtils.TakesCompletionHandlerArity2, __a2: object, __a3: object) -> java.util.concurrent.CompletableFuture: ...

    @overload
    @staticmethod
    def completable(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.AsyncUtils.TakesCompletionHandlerArity3, __a2: object, __a3: object, __a4: object) -> java.util.concurrent.CompletableFuture: ...

    @overload
    @staticmethod
    def completable(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.AsyncUtils.TakesCompletionHandlerArity4, __a2: object, __a3: object, __a4: object, __a5: object) -> java.util.concurrent.CompletableFuture: ...

    @staticmethod
    def copyTo(__a0: java.util.concurrent.CompletableFuture) -> java.util.function.BiFunction: ...

    @staticmethod
    def defensive(__a0: ghidra.async.AsyncUtils.TemperamentalRunnable) -> None: ...

    @overload
    @staticmethod
    def each(__a0: ghidra.async.TypeSpec, __a1: java.util.Iterator, __a2: ghidra.async.loop.AsyncLoopSecondActionConsumes) -> java.util.concurrent.CompletableFuture: ...

    @overload
    @staticmethod
    def each(__a0: ghidra.async.TypeSpec, __a1: java.util.Iterator, __a2: ghidra.async.loop.AsyncLoopFirstActionConsumesAndProduces, __a3: ghidra.async.TypeSpec, __a4: ghidra.async.loop.AsyncLoopSecondActionConsumes) -> java.util.concurrent.CompletableFuture: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def handle(__a0: java.util.concurrent.CompletableFuture, __a1: object, __a2: java.nio.channels.CompletionHandler) -> None: ...

    def hashCode(self) -> int: ...

    @overload
    @staticmethod
    def loop(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.loop.AsyncLoopOnlyActionRuns) -> java.util.concurrent.CompletableFuture: ...

    @overload
    @staticmethod
    def loop(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.loop.AsyncLoopFirstActionProduces, __a2: ghidra.async.TypeSpec, __a3: ghidra.async.loop.AsyncLoopSecondActionConsumes) -> java.util.concurrent.CompletableFuture: ...

    @staticmethod
    def nil() -> java.util.concurrent.CompletableFuture: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    @staticmethod
    def sequence(__a0: ghidra.async.TypeSpec) -> ghidra.async.seq.AsyncSequenceWithoutTemp: ...

    @overload
    @staticmethod
    def sequence(__a0: java.util.concurrent.CompletableFuture) -> ghidra.async.seq.AsyncSequenceWithoutTemp: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def unwrapThrowable(__a0: java.lang.Throwable) -> java.lang.Throwable: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


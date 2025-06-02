from typing import List
import ghidra.app.util.bin
import ghidra.app.util.importer
import ghidra.app.util.opinion
import ghidra.framework.model
import ghidra.program.model.lang
import ghidra.util.task
import java.io
import java.lang
import java.util.function


class AutoImporter(object):
    """
    Utility methods to do Program imports automatically (without requiring user interaction)
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @overload
    @staticmethod
    def importAsBinary(bytes: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: unicode, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.Loaded:
        """
        Automatically imports the given {@link ByteProvider} bytes with the {@link BinaryLoader}, 
         using the given language and compiler specification.
         <p>
         Note that when the import completes, the returned {@link Loaded} {@link Program} is 
         not saved to a project.  That is the responsibility of the caller (see 
         {@link Loaded#save(Project, MessageLog, TaskMonitor)}).
         <p>
         It is also the responsibility of the caller to release the returned {@link Loaded} 
         {@link Program} with {@link Loaded#release(Object)} when it is no longer needed.
        @param bytes The bytes to import
        @param project The {@link Project}.  Loaders can use this to take advantage of existing
           {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
           libraries. Could be null if there is no project.
        @param projectFolderPath A suggested project folder path for the {@link Loaded} 
           {@link Program}. This is just a suggestion, and a {@link Loader} implementation 
           reserves the right to change it the {@link Loaded} result. The {@link Loaded} result 
           should be queried for its true project folder paths using 
           {@link Loaded#getProjectFolderPath()}.
        @param language The desired {@link Language}
        @param compilerSpec The desired {@link CompilerSpec compiler specification}
        @param consumer A consumer
        @param messageLog The log
        @param monitor A task monitor
        @return The {@link Loaded} {@link Program} (created but not saved)
        @throws IOException if there was an IO-related problem loading
        @throws CancelledException if the operation was cancelled
        @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
        @throws InvalidNameException if an invalid {@link Program} name was used during load
        @throws VersionException if there was an issue with database versions, probably due to a 
           failed language upgrade
        @throws LoadException if nothing was loaded
        """
        ...

    @overload
    @staticmethod
    def importAsBinary(file: java.io.File, project: ghidra.framework.model.Project, projectFolderPath: unicode, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.Loaded:
        """
        Automatically imports the given {@link File} with the {@link BinaryLoader}, using the given
         language and compiler specification.
         <p>
         Note that when the import completes, the returned {@link Loaded} {@link Program} is 
         not saved to a project.  That is the responsibility of the caller (see 
         {@link Loaded#save(Project, MessageLog, TaskMonitor)}).
         <p>
         It is also the responsibility of the caller to release the returned {@link Loaded} 
         {@link Program} with {@link Loaded#release(Object)} when it is no longer needed.
        @param file The {@link File} to import
        @param project The {@link Project}.  Loaders can use this to take advantage of existing
           {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
           libraries. Could be null if there is no project.
        @param projectFolderPath A suggested project folder path for the {@link Loaded} 
           {@link Program}. This is just a suggestion, and a {@link Loader} implementation 
           reserves the right to change it for the {@link Loaded} result. The {@link Loaded} result 
           should be queried for its true project folder paths using 
           {@link Loaded#getProjectFolderPath()}.
        @param language The desired {@link Language}
        @param compilerSpec The desired {@link CompilerSpec compiler specification}
        @param consumer A consumer
        @param messageLog The log
        @param monitor A task monitor
        @return The {@link Loaded} {@link Program} (created but not saved)
        @throws IOException if there was an IO-related problem loading
        @throws CancelledException if the operation was cancelled
        @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
        @throws InvalidNameException if an invalid {@link Program} name was used during load
        @throws VersionException if there was an issue with database versions, probably due to a 
           failed language upgrade
        @throws LoadException if nothing was loaded
        """
        ...

    @staticmethod
    def importByLookingForLcs(file: java.io.File, project: ghidra.framework.model.Project, projectFolderPath: unicode, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults:
        """
        Automatically imports the given {@link File} with the best matching {@link Loader} that
         supports the given language and compiler specification.
         <p>
         Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
         saved to a project.  That is the responsibility of the caller (see 
         {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
         <p>
         It is also the responsibility of the caller to release the returned {@link Loaded} 
         {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
        @param file The {@link File} to import
        @param project The {@link Project}.  Loaders can use this to take advantage of existing
           {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
           libraries. Could be null if there is no project.
        @param projectFolderPath A suggested project folder path for the {@link Loaded} 
           {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
           reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
           should be queried for their true project folder paths using 
           {@link Loaded#getProjectFolderPath()}.
        @param language The desired {@link Language}
        @param compilerSpec The desired {@link CompilerSpec compiler specification}
        @param consumer A consumer
        @param messageLog The log
        @param monitor A task monitor
        @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
           (created but not saved)
        @throws IOException if there was an IO-related problem loading
        @throws CancelledException if the operation was cancelled
        @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
        @throws InvalidNameException if an invalid {@link Program} name was used during load
        @throws VersionException if there was an issue with database versions, probably due to a 
           failed language upgrade
        @throws LoadException if nothing was loaded
        """
        ...

    @overload
    @staticmethod
    def importByUsingBestGuess(provider: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: unicode, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults:
        """
        Automatically imports the give {@link ByteProvider bytes} with the best matching 
         {@link Loader} for the {@link ByteProvider}'s format.
         <p>
         Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
         saved to a project.  That is the responsibility of the caller (see 
         {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
         <p>
         It is also the responsibility of the caller to release the returned {@link Loaded} 
         {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
        @param provider The bytes to import
        @param project The {@link Project}.  Loaders can use this to take advantage of existing
           {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
           libraries. Could be null if there is no project.
        @param projectFolderPath A suggested project folder path for the {@link Loaded} 
           {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
           reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
           should be queried for their true project folder paths using 
           {@link Loaded#getProjectFolderPath()}.
        @param consumer A consumer
        @param messageLog The log
        @param monitor A task monitor
        @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
           (created but not saved)
        @throws IOException if there was an IO-related problem loading
        @throws CancelledException if the operation was cancelled
        @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
        @throws InvalidNameException if an invalid {@link Program} name was used during load
        @throws VersionException if there was an issue with database versions, probably due to a 
           failed language upgrade
        @throws LoadException if nothing was loaded
        """
        ...

    @overload
    @staticmethod
    def importByUsingBestGuess(file: java.io.File, project: ghidra.framework.model.Project, projectFolderPath: unicode, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults:
        """
        Automatically imports the given {@link File} with the best matching {@link Loader} for the
         {@link File}'s format.
         <p>
         Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
         saved to a project.  That is the responsibility of the caller (see 
         {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
         <p>
         It is also the responsibility of the caller to release the returned {@link Loaded} 
         {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
        @param file The {@link File} to import
        @param project The {@link Project}.  Loaders can use this to take advantage of existing
           {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
           libraries. Could be null if there is no project.
        @param projectFolderPath A suggested project folder path for the {@link Loaded} 
           {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
           reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
           should be queried for their true project folder paths using 
           {@link Loaded#getProjectFolderPath()}.
        @param consumer A consumer
        @param messageLog The log
        @param monitor A task monitor
        @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
           (created but not saved)
        @throws IOException if there was an IO-related problem loading
        @throws CancelledException if the operation was cancelled
        @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
        @throws InvalidNameException if an invalid {@link Program} name was used during load
        @throws VersionException if there was an issue with database versions, probably due to a 
           failed language upgrade
        @throws LoadException if nothing was loaded
        """
        ...

    @staticmethod
    def importByUsingSpecificLoaderClass(__a0: java.io.File, __a1: ghidra.framework.model.Project, __a2: unicode, __a3: java.lang.Class, __a4: List[object], __a5: object, __a6: ghidra.app.util.importer.MessageLog, __a7: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults: ...

    @staticmethod
    def importByUsingSpecificLoaderClassAndLcs(__a0: java.io.File, __a1: ghidra.framework.model.Project, __a2: unicode, __a3: java.lang.Class, __a4: List[object], __a5: ghidra.program.model.lang.Language, __a6: ghidra.program.model.lang.CompilerSpec, __a7: object, __a8: ghidra.app.util.importer.MessageLog, __a9: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults: ...

    @overload
    @staticmethod
    def importFresh(provider: ghidra.app.util.bin.ByteProvider, project: ghidra.framework.model.Project, projectFolderPath: unicode, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate, loadSpecChooser: ghidra.app.util.importer.LoadSpecChooser, importNameOverride: unicode, optionChooser: ghidra.app.util.importer.OptionChooser) -> ghidra.app.util.opinion.LoadResults:
        """
        Automatically imports the given {@link ByteProvider bytes} with advanced options.
         <p>
         Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
         saved to a project.  That is the responsibility of the caller (see 
         {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
         <p>
         It is also the responsibility of the caller to release the returned {@link Loaded} 
         {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
        @param provider The bytes to import
        @param project The {@link Project}.  Loaders can use this to take advantage of existing
           {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
           libraries. Could be null if there is no project.
        @param projectFolderPath A suggested project folder path for the {@link Loaded} 
           {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
           reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
           should be queried for their true project folder paths using 
           {@link Loaded#getProjectFolderPath()}.
        @param loaderFilter A {@link Predicate} used to choose what {@link Loader}(s) get used
        @param loadSpecChooser A {@link LoadSpecChooser} used to choose what {@link LoadSpec}(s) get
           used
        @param importNameOverride The name to use for the imported thing.  Null to use the 
           {@link Loader}'s preferred name.
        @param optionChooser A {@link OptionChooser} used to choose what {@link Loader} options get
           used
        @param consumer A consumer
        @param messageLog The log
        @param monitor A task monitor
        @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
           (created but not saved)
        @throws IOException if there was an IO-related problem loading
        @throws CancelledException if the operation was cancelled
        @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
        @throws InvalidNameException if an invalid {@link Program} name was used during load
        @throws VersionException if there was an issue with database versions, probably due to a 
           failed language upgrade
        @throws LoadException if nothing was loaded
        """
        ...

    @overload
    @staticmethod
    def importFresh(file: java.io.File, project: ghidra.framework.model.Project, projectFolderPath: unicode, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor, loaderFilter: java.util.function.Predicate, loadSpecChooser: ghidra.app.util.importer.LoadSpecChooser, importNameOverride: unicode, optionChooser: ghidra.app.util.importer.OptionChooser) -> ghidra.app.util.opinion.LoadResults:
        """
        Automatically imports the given {@link File} with advanced options.
         <p>
         Note that when the import completes, the returned {@link Loaded} {@link Program}s are not 
         saved to a project.  That is the responsibility of the caller (see 
         {@link LoadResults#save(Project, Object, MessageLog, TaskMonitor)}).
         <p>
         It is also the responsibility of the caller to release the returned {@link Loaded} 
         {@link Program}s with {@link LoadResults#release(Object)} when they are no longer needed.
        @param file The {@link File} to import
        @param project The {@link Project}.  Loaders can use this to take advantage of existing
           {@link DomainFolder}s and {@link DomainFile}s to do custom behaviors such as loading
           libraries. Could be null if there is no project.
        @param projectFolderPath A suggested project folder path for the {@link Loaded} 
           {@link Program}s. This is just a suggestion, and a {@link Loader} implementation 
           reserves the right to change it for each {@link Loaded} result. The {@link Loaded} results 
           should be queried for their true project folder paths using 
           {@link Loaded#getProjectFolderPath()}.
        @param loaderFilter A {@link Predicate} used to choose what {@link Loader}(s) get used
        @param loadSpecChooser A {@link LoadSpecChooser} used to choose what {@link LoadSpec}(s) get
           used
        @param importNameOverride The name to use for the imported thing.  Null to use the 
           {@link Loader}'s preferred name.
        @param optionChooser A {@link OptionChooser} used to choose what {@link Loader} options get
           used
        @param consumer A consumer
        @param messageLog The log
        @param monitor A task monitor
        @return The {@link LoadResults} which contains one ore more {@link Loaded} {@link Program}s 
           (created but not saved)
        @throws IOException if there was an IO-related problem loading
        @throws CancelledException if the operation was cancelled
        @throws DuplicateNameException if the load resulted in a {@link Program} naming conflict
        @throws InvalidNameException if an invalid {@link Program} name was used during load
        @throws VersionException if there was an issue with database versions, probably due to a 
           failed language upgrade
        @throws LoadException if nothing was loaded
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


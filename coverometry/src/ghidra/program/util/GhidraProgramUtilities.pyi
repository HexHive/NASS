import ghidra.framework.plugintool
import ghidra.program.model.listing
import java.lang


class GhidraProgramUtilities(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getCurrentProgram(tool: ghidra.framework.plugintool.PluginTool) -> ghidra.program.model.listing.Program:
        """
        Returns the current program for the given tool or null if no program is open.
        @param tool the tool get get the current program for
        @return the current program for the given tool or null if no program is open
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isAnalyzed(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the program has been analyzed at least once.
        @param program the program to test to see if it has been analyzed
        @return true if the program has been analyzed at least once.
        """
        ...

    @staticmethod
    def markProgramAnalyzed(program: ghidra.program.model.listing.Program) -> None:
        """
        Marks the program has having been analyzed
        @param program the program to set property
        """
        ...

    @staticmethod
    def markProgramNotToAskToAnalyze(program: ghidra.program.model.listing.Program) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def resetAnalysisFlags(program: ghidra.program.model.listing.Program) -> None:
        """
        Resets the analysis flags to the program defaults
         With this reset, the user will be prompted to analyze the
         program the next time it is opened.
        @param program the program whose analysis flags should be reset
        """
        ...

    @staticmethod
    def shouldAskToAnalyze(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the user should be asked to analyze. They will only be asked if the program
         hasn't already been analyzed (analyzed flag property is false or null) or the
         "ask to analyze" flag property is true or null (default is true unless explicitly set to 
         false).
        @param program the program to check for the property
        @return true if the user should be prompted to analyze the program
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...


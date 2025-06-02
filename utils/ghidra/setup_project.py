from ghidra.app.script import GhidraScript

state = getState()
project = state.getProject()
#print(project)
program = currentProgram
#print(getCurrentAnalysisOptionsAndValues(program))
#setAnalysisOptions(program, {u'Decompiler Switch Analysis': u'false', u'DWARF': u'false', u'Decompiler Parameter ID.Commit Data Types': u'false'})
#setAnalysisOptions(program, {u'Demangler GNU': u'false'})
#setAnalysisOptions(program, {u'Demangler GNU': u'false', u'DWARF': u'false'})
#setAnalysisOptions(program, {u'Demangler GNU.Apply Function Signatures': u'false',u'Demangler GNU.Apply Function Calling Conventions': u'false', u'DWARF': u'false'})
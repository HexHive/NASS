import os
from argparse import ArgumentParser
import json
from coverazza import parser
from coverazza.parser import DrCov2MT2Entry
import logging
import jep
from java.io import File
import networkx as nx

from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex

################################################################################
# TYPING
################################################################################
from ghidra.app.util.headless import HeadlessScript
from ghidra.program.model.listing import Program
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressFactory
from ghidra.app.services import ProgramManager
from ghidra.app.util.headless import HeadlessScript
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import Address

from ghidra.util.task import TaskMonitor

################################################################################
# LOGGING
################################################################################
FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s " "%(message)s"
logging.basicConfig(
    format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG
)
log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

DR_COV_FILENAME: str = "merged-cov.log"
MAPPED_OBJS_DIRNAME: str = "objs"
CFG_CACHE: dict[int, nx.DiGraph] = {}


################################################################################
# CODE
################################################################################


class CoverazzaException(Exception):
    pass


def debug():
    print(f"Loader: {__loader__}")
    print(f"jep: {jep}")
    print(f"File: {File}")
    # print(f"Loader: {globals()}")
    print(f"func: {importFile}")
    state = getState()
    project = state.getProject()
    program = state.getCurrentProgram()
    locator = project.getProjectData().getProjectLocator()
    print("type(state):           {}".format(type(state)))
    print("type(project):         {}".format(type(project)))
    print("type(program):         {}".format(type(program)))
    print("type(locator):         {}".format(type(locator)))
    print("Project Name:          {}".format(locator.getName()))
    print(
        "Files in this project: {}".format(
            project.getProjectData().getFileCount()
        )
    )
    print("Is a remote project:   {}".format(locator.isTransient()))
    print("Project location:      {}".format(locator.getLocation()))
    print("Project directory:     {}".format(locator.getProjectDir()))
    print("Lock file:             {}".format(locator.getProjectLockFile()))
    print("Marker file:           {}".format(locator.getMarkerFile()))
    print("Project URL:           {}".format(locator.getURL()))


def debug2():
    state = getState()
    project = state.getProject()
    locator = project.getProjectData().getProjectLocator()
    projectMgr = project.getProjectManager()
    activeProject = projectMgr.getActiveProject()
    projectData = activeProject.getProjectData()
    rootFolder = projectData.getRootFolder()

    print("type(state):           {}".format(type(state)))
    print("type(project):         {}".format(type(project)))
    print("type(projectMgr):      {}".format(type(projectMgr)))
    print("type(activeProject):   {}".format(type(activeProject)))
    print("type(projectData):     {}".format(type(projectData)))
    print("type(rootFolder):      {}".format(type(rootFolder)))

    projectName = locator.getName()
    fileCount = projectData.getFileCount()
    files = rootFolder.getFiles()

    print("The project '{}' has {} files in it:".format(projectName, fileCount))
    for file in files:
        print("\t{}".format(file))


def getAddress(program: Program, offset: int) -> Address:
    return (
        program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    )


def is_new_project() -> bool:
    state = getState()
    project = state.getProject()
    projectData = project.getProjectData()
    fileCount = projectData.getFileCount()
    return fileCount == 0


def get_programs() -> list[Program]:
    state = getState()
    project = state.getProject()
    projectData = project.getProjectData()
    rootFolder = projectData.getRootFolder()
    files = rootFolder.getFiles()

    programs: list[Program] = []
    for file in files:
        program = file.getDomainObject(project, True, False, TaskMonitor.DUMMY)

        programs.append(program)

    return programs


def get_cfg_containing(program: Program, addr: int) -> nx.DiGraph:

    fm = program.getFunctionManager()
    func = fm.getFunctionContaining(getAddress(program, addr))

    if not func:
        raise CoverazzaException(f"Basic block at {addr:#x} not in function.")

    bm = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()

    if func.getEntryPoint().getOffset() in CFG_CACHE:
        g = CFG_CACHE[func.getEntryPoint().getOffset()]

        if addr not in g.nodes:
            log.info(f"Basic block at {addr:#x} not in nodes.")
            blocks = bm.getCodeBlocksContaining(
                getAddress(program, addr), monitor
            )

            assert len(blocks) == 1, "Why is this not 1?"
            for bb in blocks:
                print(f"\t[*] first start {bb.getFirstStartAddress()} ")

                predecessor = bb.getFirstStartAddress().getOffset()
                # this should remove the edges
                successors = g.successors(predecessor)
                g.remove_node(predecessor)
                g.add_edge(predecessor, addr)

                g.nodes[predecessor]["visited"] = False
                g.nodes[addr]["visited"] = False

                for suc in successors:
                    g.add_edge(addr, suc)

                # dest = bb.getDestinations(monitor)
                # while dest.hasNext():
                #     dbb = dest.next()
                #     print(f"\t[*] {dbb} ")
        return g

    g = nx.DiGraph()
    CFG_CACHE[func.getEntryPoint().getOffset()] = g

    log.info(f"Basic block details for function '{func.getName()}':")
    blocks = bm.getCodeBlocksContaining(func.getBody(), monitor)

    # print first block
    log.info(f"\t[*] {func.getEntryPoint()}")

    g.add_node(addr, attr={"visited": False})

    while blocks.hasNext():
        bb = blocks.next()
        dest = bb.getDestinations(monitor)
        while dest.hasNext():
            dbb = dest.next()

            if not func.getBody().contains(dbb.getDestinationAddress()):
                # dst is a node in another function
                continue

            src = bb.getFirstStartAddress().getOffset()
            dst = dbb.getDestinationAddress().getOffset()

            g.add_edge(src, dst)

            g.nodes[src]["visited"] = False
            g.nodes[dst]["visited"] = False

            # For some odd reason `getCodeBlocksContaining()` and `.next()`
            # return the root basic block after CALL instructions (x86). To filter
            # these out, we use `getFunctionAt()` which returns `None` if the address
            # is not the entry point of a function. See:
            # https://github.com/NationalSecurityAgency/ghidra/issues/855
            # if not fm.getFunctionAt(dbb.getDestinationAddress()):
            #     print("\t[*] {} ".format(dbb))

    assert addr in g.nodes, f"addr {addr} not in nodes."

    return g


def graph(program: Program):
    """scratch code for function call graph within a binary"""
    digraph = DirectedGraph()
    listing = program.getListing()
    fm = program.getFunctionManager()

    funcs = fm.getFunctions(True)  # True mean iterate forward
    for func in funcs:
        # Add function vertices
        print(
            "Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint())
        )  # FunctionDB
        digraph.add(Vertex(func))

        # Add edges for static calls
        entryPoint = func.getEntryPoint()
        instructions = listing.getInstructions(entryPoint, True)
        for instruction in instructions:
            addr = instruction.getAddress()
            oper = instruction.getMnemonicString()
            if oper == "CALL":
                print("    0x{} : {}".format(addr, instruction))
                flows = instruction.getFlows()
                if len(flows) == 1:
                    target_addr = "0x{}".format(flows[0])
                    digraph.add(
                        Edge(
                            Vertex(func),
                            Vertex(fm.getFunctionAt(getAddress(target_addr))),
                        )
                    )
    return digraph


def load_obj(obj_path: str, base: int) -> Program:
    log.info(f"Loading {obj_path} at {hex(base)}")
    f = File(obj_path)
    program: Program = importFile(f)
    base_addr = (
        program.getAddressFactory().getDefaultAddressSpace().getAddress(base)
    )
    id = program.startTransaction("Change base")
    program.setImageBase(base_addr, True)
    program.endTransaction(id, True)

    print(f"{program}")
    saveProgram(program)
    return program


def parse_args():
    arg_parser = ArgumentParser(
        description="Covometry coverage approximator",
        prog="script",
        prefix_chars="+",
    )
    arg_parser.add_argument(
        "+d",
        "++dir",
        required=True,
        help="Service directory containing DrCov file and memory objects.",
    )
    args = arg_parser.parse_args(args=getScriptArgs())
    return args


def main():
    logging.info("Initializing...")

    args = parse_args()
    service_dir: str = args.dir

    # parse the DrCov file
    dr_cov_path = os.path.join(service_dir, DR_COV_FILENAME)
    if not os.path.isfile(dr_cov_path):
        raise FileNotFoundError(f"{dr_cov_path} does not exist.")

    mt_rows: list[DrCov2MT2Entry] = parser.parse(dr_cov_path)

    # filter drcov module table rows for memory objects covered
    mt_rows_filtered = [mt_row for mt_row in mt_rows if mt_row.bbs]

    # check if all covered memory objects are present
    mapped_objs_dir = os.path.join(service_dir, MAPPED_OBJS_DIRNAME)
    mem_objs = os.listdir(mapped_objs_dir)
    for mt_row in mt_rows_filtered:
        mem_obj_name = os.path.basename(mt_row.path)
        if mem_obj_name not in mem_objs:
            raise FileNotFoundError(f"{mem_obj_name} not found.")

    if is_new_project():
        # load memory objects in Ghidra
        programs: list[Program] = []
        for mt_row in mt_rows_filtered:
            path = os.path.join(mapped_objs_dir, os.path.basename(mt_row.path))
            programs.append(load_obj(path, mt_row.base))

        # analyze programs
        for program in programs:
            id = program.startTransaction("Analyze program")
            analyzeAll(program)
            program.endTransaction(id, True)
            saveProgram(program)
    else:
        programs: list[Program] = get_programs()

    fcfgs: set[nx.DiGraph] = set()
    for idx, row in enumerate(mt_rows_filtered):
        for bb in sorted(list(set(row.bbs))):
            program = programs[idx]
            base = row.base

            # the rebased bb address is the node id in our graph
            rebased_bb = base + bb

            assert (
                row.base < rebased_bb and rebased_bb < row.end
            ), "bb not in module"

            try:
                # get the cfg of the func this bb belongs to
                fcfg = get_cfg_containing(program, rebased_bb)
            except CoverazzaException as e:
                log.error(e)
                continue

            # mark node as visited
            fcfg.nodes[rebased_bb]["visited"] = True
            fcfgs.add(fcfg)

            # print("DiGraph info:")
            # for u, v in fcfg.edges:
            #     print(f"  Edge from {u:#x} to {v:#x}")

    covered_total = 0
    nodes_total = 0
    for fcfg in fcfgs:
        covered = 0
        for n in fcfg.nodes:
            # log.info(f"Node {n:#x}")
            if fcfg.nodes[n]["visited"]:
                covered += 1

        covered_total += covered
        nodes_total += len(fcfg.nodes)
        # log.info(f"Coverage {covered}/{len(fcfg.nodes)}")

    log.info(f"Coverage total {covered_total}/{nodes_total}")
    cov_file = os.path.join(service_dir, "cov.json")
    log.info(f"Writing to {cov_file}")
    with open(cov_file, "w") as f:
        json.dump({"covered": covered_total, "total": nodes_total}, f)


if __name__ == "__main__":
    main()

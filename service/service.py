import adb
import os
import time
import re
import logging
import sys
import tempfile

from typing import List

base_path = os.path.dirname(__file__)
sys.path.append(os.path.join(base_path, ".."))
sys.path.append(os.path.join(base_path, "..", "..", "utils"))

from config import TARGET_DIR
import utils.utils as utils


log = logging.getLogger(__name__)


class ServiceNotFound(Exception):
    pass


class PMPathFailed(Exception):
    pass


class CallTimeout(Exception):
    pass


class Owner:
    def __init__(self, pid, proc_name) -> None:
        self.pid = pid
        self.proc_name = proc_name

    def __str__(self) -> str:
        return f"{self.pid}:{self.proc_name}"

    def __repr__(self) -> str:
        return f"{self.pid}:{self.proc_name}"


class User:
    def __init__(self, pid, proc_name) -> None:
        self.pid = pid
        self.proc_name = proc_name

    def __str__(self) -> str:
        return f"{self.pid}:{self.proc_name}"

    def __repr__(self) -> str:
        return f"{self.pid}:{self.proc_name}"


class Arg:
    def __init__(self, argtype, db_id=None) -> None:
        self.argtype = argtype
        self.constr = None
        self.db_id = db_id

    def __str__(self) -> str:
        return f"Arg({self.argtype})"

    def __repr__(self) -> str:
        return f"Arg(A{self.argtype})"


class Cmd:
    def __init__(
        self, cmd_id, args=[], args_enumerated=False, valid=True, db_id=None
    ) -> None:
        self.cmd_id = cmd_id
        self.args = args
        self.db_id = db_id
        self.valid = valid
        self.info = None
        self.constraints = None
        self.args_enumerated = args_enumerated
        # @TODO: probably need to do more

    def __str__(self) -> str:
        return f"Cmd({self.cmd_id}:{self.args})"

    def __repr__(self) -> str:
        return f"Cmd({self.cmd_id}:{self.args})"


class Service:
    def __init__(
        self,
        service_name,
        device_name,
        arch=None,
        binary_path=None,
        is_app=None,
        is_svcsvr=None,
        is_native=None,
        onTransact=None,
        cmds=[],
        cmd_ids_enumerated=False,
        db_id=None,
        meta_device_id=None
    ) -> None:
        self.bdsm_setup = False
        self.service_name = service_name
        self.device = device_name
        if meta_device_id is None:
            self.meta_device_id = self.device
        else:
            self.meta_device_id = meta_device_id
        self.arch = arch
        self.binary_path = binary_path
        self.is_app = is_app
        self.is_svcsvr = is_svcsvr
        self.is_native = is_native
        self.onTransact = onTransact
        self.db_id = db_id
        self.owner = None
        self.pid = None
        self.users = None
        self.proc_map = None
        self.local_path = None
        self.md5sum = "UNKNOWN"
        self.cmds = cmds
        self.cmd_ids_enumerated = cmd_ids_enumerated
        self._out_dir = os.path.join(TARGET_DIR, self.meta_device_id, self.service_name)

    def cmd_ids_iterated(self):
        return self.cmd_ids_enumerated

    def get_cmd_ids(self):
        out = []
        for cmd in self.cmds:
            out.append(cmd.cmd_id)
        return out

    def adb_data(self):
        log.error(f"adb_data called on defualt implmenetation")
        print(f"adb_data called on defualt implmenetation")

    def wipe_cache(self):
        if not os.path.isdir(self._out_dir):
            return

        for entry in os.listdir(self._out_dir):
            file_path = os.path.join(self._out_dir, entry)
            if os.path.isfile(file_path):
                log.debug(f"removing {file_path}")
                os.unlink(file_path)

    def download_binary(self, binary_path: str) -> str:
        """Download file from remote if it does not exist locally yet.

        Args:
            binary_path (str): Path to binary on remote.

        Returns:
            str: Local path to the file.
        """
        self.local_path = self._out_dir
        final_path = os.path.join(self._out_dir, os.path.basename(binary_path))
        if not os.path.exists(final_path):
            log.debug(f"downloading : {binary_path}")
            os.system(f"mkdir -p {self._out_dir}")
            adb.pull_privileged(
                binary_path, self._out_dir, device_id=self.device
            )
        else:
            md5 = utils.get_md5(final_path)
            md5_remote = adb.get_md5_filehash(binary_path, device_id=self.device)
            if md5 != md5_remote:
                log.debug(f"downloading : {binary_path}")
                os.system(f"mkdir -p {self._out_dir}")
                adb.pull_privileged(
                    binary_path, self._out_dir, device_id=self.device
                ) 
        return final_path

    def get_arch(self):
        out, err = adb.execute_command("uname -m", device_id=self.device)
        out = out.decode()
        out = out.strip("\n")
        log.debug(f"architecture for {self.device}: {out}")
        return out

    def get_proc_maps(self):
        if self.pid is None:
            log.error(f"called get_proc_maps without pid setting")
            return None
        tmp_file = tempfile.mktemp()
        adb.pull_privileged(
            f"/proc/{self.pid}/maps", tmp_file, device_id=self.device
        )
        proc_maps = utils.parse_proc_maps(open(tmp_file).read())
        os.remove(tmp_file)
        return proc_maps

    def get_dependencies(self):
        service_binary = os.path.basename(self.binary_path)
        onTransact_binary = os.path.basename(self.onTransact.bin)

        local_onTransact_binary_path = os.path.join(
            self._out_dir,
            onTransact_binary,
        )

        local_service_binary_path = os.path.join(
            self._out_dir,
            service_binary,
        )

        # ensure we have both binaries locally
        if not os.path.isfile(local_service_binary_path):
            self.download_binary(self.binary_path)

        if not os.path.isfile(local_onTransact_binary_path):
            self.download_binary(self.onTransact.bin)

        libs_onTransact = utils.get_libs(local_onTransact_binary_path)
        libs_base = utils.get_libs(local_service_binary_path)

        libs_base.append(service_binary)

        # iterate over onTransact dump and extract relevant instrumentation ranges

        onT_libs = []
        ontransact_libs = list(set(
            utils.onTransact_dump_libs(
                os.path.join(TARGET_DIR, self.meta_device_id, self.service_name, 
                             "onTransact_vtable.txt"))
        ))

        for lib in ontransact_libs:
            local_path = os.path.join(self._out_dir, os.path.basename(lib))
            if not os.path.isfile(local_path):
                self.download_binary(lib)
            onT_libs += utils.get_libs(local_path) 

        libs = list(set(libs_base + libs_onTransact + onT_libs))
        return libs

    def setup(self):
        log.error(f"setup called on base class")
        print(f"setup called on base class")
        return None

    def get_owner(self):
        log.error(f"get_owner called on base class")
        print(f"get_owner called on base class")
        return None

    def svc_is_svcsvr(self):
        if self.owner.proc_name == "system_server":
            log.info(f"{self.service_name} is system_server service")
            return True
        return False

    def svc_is_app(self):
        if self.owner is None:
            log.error(f"run get_owner before this!")
            exit(-1)
        if self.owner.proc_name == "system_server":
            return False
        # check if process is app_process something
        out, err = adb.execute_privileged_command(
            f"realpath /proc/{self.pid}/exe", device_id=self.device
        )
        if len(err) > 2 or len(out) < 2:
            log.error(f"realpath /proc/{self.pid}/exe failed")
            raise Exception
        bin_name = out.decode()
        bin_name = bin_name.strip("\n")
        if "app_process" in bin_name:
            log.info(f"{self.service_name} is an app service")
            return True
        return False

    def get_bin_path(self):
        out, err = adb.execute_privileged_command(
            f"realpath /proc/{self.pid}/exe", device_id=self.device
        )
        if len(err) > 2 or len(out) < 2:
            print(f"realpath /proc/{self.pid}/exe failed: {err}")
            log.error(f"realpath /proc/{self.pid}/exe failed: {err}")
            raise Exception
        bin_name = out.decode()
        bin_name = bin_name.strip("\n")
        if self.owner.proc_name == "system_server":
            return bin_name
        if "app_process" in os.path.basename(bin_name):
            # it's an app
            out, err = adb.execute_privileged_command(
                f"pm path {self.owner.proc_name}", device_id=self.device
            )
            if len(err) > 2 or len(out) < 2:
                log.error(f"pm path {self.owner.proc_name} failed")
                return None
            bin_name = out.decode().strip("\n")
        log.info(f"binary path for {self.service_name}: {bin_name}")
        return bin_name

    def get_users(self):
        log.error(f"get_users called on base class!")
        return None

    def call(self, cmd_id, args):
        log.error(f"call used on base class")
        return None

    def check_service(self, timeout=60*3):
        pid = adb.get_service_pid(
            self.service_name,
            self.device,
            timeout=timeout,
        )
        if pid is None:
            return False
        # TODO: check if pid changed
        return True

    def wait_for_service(self, tries=20):
        while (
            adb.get_service_pid(
                self.service_name,
                self.device,
                timeout=300,
            )
            is None
        ):
            if tries < 0:
                raise adb.ADBTimeoutException
            log.info("waiting for service")
            time.sleep(1)
            tries = tries - 1

        self.pid = adb.get_service_pid(
            self.service_name,
            self.device,
            timeout=300,
        )

    def __str__(self) -> str:
        return f"{self.service_name}: {self.device}, {self.binary_path}"

    def __repr__(self) -> str:
        return f"{self.service_name}: {self.device}, {self.binary_path}"




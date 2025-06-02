import adb
import os
import re
import logging
import sys

base_path = os.path.dirname(__file__)
sys.path.append(base_path)
sys.path.append(os.path.join(base_path, "..", "utils"))
from .service import Owner, User, Service, ServiceNotFound

"""
BDSM caller uses https://newandroidbook.com/tools/bdsm.html
"""

log = logging.getLogger(__name__)
bdsm_dir_path = os.path.join(base_path, "..", "tools", "bdsm")
pid_dumper_dir_path = os.path.join(base_path, "..", "tools", "pid_dump")
remote_path = "/data/local/tmp/bdsm"


class BDSM(Service):
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
        init_adb=True,
    ) -> None:
        super().__init__(
            service_name,
            device_name,
            arch,
            binary_path,
            is_app,
            is_svcsvr,
            is_native,
            onTransact,
            cmds,
            cmd_ids_enumerated,
            db_id,
        )
        if init_adb:  # collect data specific to a currently running service
            self.adb_data()

    @classmethod
    def fromService(cls, service: Service):
        return cls(
            service_name=service.service_name,
            device_name=service.device,
            arch=service.arch,
            binary_path=service.binary_path,
            is_app=service.is_app,
            is_svcsvr=service.is_svcsvr,
            is_native=service.is_native,
            onTransact=service.onTransact,
            cmds=service.cmds,
            cmd_ids_enumerated=service.cmd_ids_enumerated,
            db_id=service.db_id,
            init_adb=False,
        )

    def adb_data(self):
        if self.arch is None:
            self.arch = self.get_arch()
        self.owner = self.get_owner()
        self.pid = self.owner.pid
        if self.binary_path is None:
            self.binary_path = self.get_bin_path()
        if self.is_app is None:
            self.is_app = self.svc_is_app()
        if self.is_svcsvr is None:
            self.is_svcsvr = self.svc_is_svcsvr()
        if self.is_native is None:
            self.is_native = not (
                self.is_app or self.is_svcsvr
            )  # and not self.is_svcsvr #TODO fix this but system server is broken rn
        self.users = self.get_users()
        self.proc_map = self.get_proc_maps()
        if self.binary_path is not None:
            self.download_binary(self.binary_path)

    def setup(self):
        bdsm_p = None
        if self.arch == "aarch64":
            bdsm_p = os.path.join(bdsm_dir_path, "bdsm")
            pid_dumper_arch = os.path.join(
                pid_dumper_dir_path, "pid_dump_arm64.so"
            )
        elif self.arch == "armv8l":
            bdsm_p = os.path.join(bdsm_dir_path, "bdsm.armv7")
            print("ADD PID DUMPER!!")
            exit(-1)
        else:
            log.error(f"unknown archtecture: {self.arch}")
            print(f"[*] unknown archtecture: {self.arch}")
            raise Exception
        _, err = adb.execute_privileged_command(
            f"mkdir -p {remote_path}", device_id=self.device
        )
        if err:
            log.error(f"failed setting up directory: {remote_path}, {err}")
            raise Exception
        bdsm_p_remote = os.path.join(remote_path, os.path.basename(bdsm_p))
        if not adb.path_exists(bdsm_p_remote, device_id=self.device):
            adb.push_privileged(bdsm_p, remote_path, device_id=self.device)
        pid_dump_p = os.path.join(pid_dumper_dir_path, pid_dumper_arch)
        pid_dump_remote = os.path.join(
            remote_path, os.path.basename(pid_dump_p)
        )
        if not adb.path_exists(pid_dump_remote, device_id=self.device):
            adb.push_privileged(pid_dump_p, remote_path, device_id=self.device)
        adb.execute_privileged_command(
            f"chmod +x {bdsm_p_remote}", device_id=self.device
        )
        adb.execute_privileged_command(
            f"chmod +x {pid_dump_remote}", device_id=self.device
        )
        log.info(f"bdsm setup on {self.device} at {bdsm_p_remote}")
        # self.bdsm_setup = True @TODO: fix this..
        return bdsm_p_remote, pid_dump_remote

    def get_owner(self):
        if not self.bdsm_setup:
            bdsm_remote, _ = self.setup()
        out, err = adb.execute_privileged_command(
            f"{bdsm_remote} users {self.service_name}", device_id=self.device
        )
        logging.debug(f"owner enumer: {out}, {err}")
        if "not found" in err.decode():
            log.error(f"{self.service_name} not found!")
            raise ServiceNotFound
        reg = r"Owner:[ ]+([0-9]+) \((.+)\)"
        reg_match = re.search(reg, out.decode())
        pid, owner = reg_match.group(1, 2)
        log.info(f"bdsm owner {self.service_name}: PID {pid}, {owner}")
        return Owner(int(pid), owner)

    def get_users(self):
        if not self.bdsm_setup:
            bdsm_remote, _ = self.setup()
        out, err = adb.execute_privileged_command(
            f"{bdsm_remote} users {self.service_name}", device_id=self.device
        )
        if "not found" in err.decode():
            log.error(f"{self.service_name} not found!")
            raise ServiceNotFound
        out = out.decode().split("\n")[1:]
        reg = r"User: +([0-9]+) \((.+)\)"
        users = []
        for user in out:
            reg_match = re.search(reg, user)
            if reg_match is None:
                continue
            pid, user = reg_match.group(1, 2)
            log.info(f"bdsm users {self.service_name}: PID {pid} {user}")
            users.append(User(int(pid), user))
        return users

    def get_bdsm_args(self, args):
        if len(args) == 0:
            return ""
        else:
            print(f"NOT IMPLEMENTED")
            exit(-1)

    def call(self, cmd_id, args, user="root", timeout=5):
        # args:
        if not self.bdsm_setup:
            bdsm_remote, pid_dumper_remote = self.setup()
        bdsm_args = self.get_bdsm_args(args)
        try:
            out, err = adb.execute_runas_command(
                f"LD_PRELOAD={pid_dumper_remote} {bdsm_remote} call {self.service_name} {cmd_id} {bdsm_args}",
                device_id=self.device,
                user=user,
                timeout=timeout,
            )
        except adb.DeviceTimeoutException as exc:
            out = exc.stdout
            err = exc.stderr
        # recover the pid
        out = out.decode()
        pid = int(out.split("\n")[0].split(": ")[-1])
        stdout = "\n".join(out.split("\n")[1:])
        logging.debug(f"bdsm called {pid} stdout:{stdout}, stderr:{err}")
        # return pid, stdout and the error
        return pid, stdout, err

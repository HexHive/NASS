import adb
import os
import re
import logging
import sys
import tempfile

base_path = os.path.dirname(__file__)
sys.path.append(base_path)
sys.path.append(os.path.join(base_path, "..", "utils"))
import utils
from .service import (
    Owner,
    User,
    Service,
    Cmd,
    ServiceNotFound,
    CallTimeout,
    PMPathFailed,
)

"""
vanilla caller uses service and dumpsys 
"""

log = logging.getLogger(__name__)
pid_dumper_dir_path = os.path.join(base_path, "..", "tools", "pid_dump")
remote_path = "/data/local/tmp/vanilla"


class Vanilla(Service):
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
        meta_device_id=None
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
            cmd_ids_enumerated=cmd_ids_enumerated,
            db_id=db_id,
            meta_device_id=meta_device_id
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
            meta_device_id = service.meta_device_id
        )

    def adb_data(self, get_users=False):
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
            self.is_native = not (self.is_app or self.is_svcsvr)
        if get_users:
            self.users = self.get_users()
        self.proc_map = self.get_proc_maps()
        if self.binary_path is not None:
            self.download_binary(self.binary_path)

    def setup(self):
        if self.arch == "aarch64":
            pid_dumper_arch = os.path.join(
                pid_dumper_dir_path, "pid_dump_arm64.so"
            )
        elif self.arch == "armv8l":
            print("ADD PID DUMPER!!")
            exit(-1)
        elif self.arch == "x86_64":
            pid_dumper_arch = os.path.join(
                pid_dumper_dir_path, "pid_dump_x86_64.so"
            )
        else:
            log.error(f"unknown archtecture: {self.arch}")
            print(f"[*] unknown archtecture: {self.arch}")
            raise Exception
        _, err = adb.execute_privileged_command(
            f"mkdir -p {remote_path}", device_id=self.device
        )
        if err:
            print(f"failed setting up directory: {remote_path}, {err}")
            log.error(f"failed setting up directory: {remote_path}, {err}")
            raise Exception
        pid_dump_p = os.path.join(pid_dumper_dir_path, pid_dumper_arch)
        pid_dump_remote = os.path.join(
            remote_path, os.path.basename(pid_dump_p)
        )
        if not adb.path_exists(pid_dump_remote, device_id=self.device):
            adb.push_privileged(pid_dump_p, remote_path, device_id=self.device)
        adb.execute_privileged_command(
            f"chmod +x {pid_dump_remote}", device_id=self.device
        )
        log.info(f"vanilla setup on {self.device} at {remote_path}")
        # self.bdsm_setup = True @TODO: fix this..
        return None, pid_dump_remote

    def pid2exe(self, pid):
        out, err = adb.execute_privileged_command(
            f"cat /proc/{pid}/cmdline", device_id=self.device
        )
        if "No such file" in err.decode():
            log.error(f"cat /proc/{pid}/cmdline failed")
            raise ServiceNotFound
        out = out.strip(b"\n")
        out = out.strip(b"\x00")
        out = out.decode()
        logging.debug(f"pid2exe: {pid}:{out}")
        return out

    def get_owner(self):
        if not self.bdsm_setup:
            _, _ = self.setup()
        pid = adb.get_service_pid(
            self.service_name,
            device_id=self.device,
        )
        owner = self.pid2exe(pid)
        log.info(f"vanilla owner {self.service_name}: PID {pid}, {owner}")
        return Owner(pid, owner)

    def get_users(self):
        if not self.bdsm_setup:
            bdsm_remote, _ = self.setup()
        out, err = adb.execute_privileged_command(
            f"dumpsys --clients {self.service_name}", device_id=self.device
        )
        if "Can't find service" in err.decode():
            log.error(f"{self.service_name} not found!")
            raise ServiceNotFound
        if b"unrecognized option" in err:
            log.error(f"no clients found...")
            return []
        out = out.decode().strip("\n").split(":")[-1].split(",")
        users = []
        for user_pid in out:
            pid = int(user_pid)
            user = self.pid2exe(pid)
            log.info(f"vanialla users {self.service_name}: PID {pid} {user}")
            users.append(User(int(pid), user))
        return users

    def get_vanilla_args(self, args):
        if len(args) == 0:
            return ""
        else:
            print(f"NOT IMPLEMENTED")
            exit(-1)

    def call(self, cmd_id, args, user="root", timeout=5):
        # args:
        if not self.bdsm_setup:
            _, pid_dumper_remote = self.setup()
        vanilla_args = self.get_vanilla_args(args)
        try:
            out, err = adb.execute_runas_command(
                f"LD_PRELOAD={pid_dumper_remote} service call {self.service_name} {cmd_id} {vanilla_args}",
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
        logging.debug(
            f"vanilla service called {pid} stdout:{stdout}, stderr:{err}"
        )
        # return pid, stdout and the error
        return pid, stdout, err

import sqlite3
import sys
import os
import tempfile

basepath = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(basepath)

from config import BINDER_DB
import data.crash_db as crash_db
import data.interface_db as interface_db
import data.binderfunc_db as binderfunc_db
import data.phase2_db as phase2_db
import data.app_handle as app_handle


"""
store all the extracted information about services etc...
Table Service:
    id | device | servicename | binary_path | architecture | is_app |  is_system_server | is_native | onTransact_bin | onTransact_entry_addr | onTransact_last_addr | onTransact_fname 
Table Interface:
    id | service_id (foreign key Service(id)) | cmd_id 
Table BinderArgs:
    id | interface_args_id | order | type | info 
Table crash:
    id | service_id | info
Table Call:
    id | crash_id (foreign key service(id)) | cmd_id | ordering | payload_data(base64)
Table callarg
    id | call_id | type | ordering 
"""


def init_db():
    interface_db.init_db(BINDER_DB)
    crash_db.init_db(BINDER_DB)
    binderfunc_db.init_db(BINDER_DB)
    phase2_db.init_db(BINDER_DB)
    app_handle.init_db(BINDER_DB)


def open_db():
    if not os.path.exists(BINDER_DB):
        init_db()
    connection = sqlite3.connect(BINDER_DB)
    return connection


def single_select(connection, query):
    out = []
    cursor = connection.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    for row in rows:
        out.append(row[0])
    return out


def insert_crashing_sequence(connection, service, calls, call_config):
    service_id = interface_db.insert_update_service(connection, service)
    crash_id = crash_db.insert_crash(connection, service_id)
    for i, call in enumerate(calls):
        call_id = crash_db.insert_call(
            connection, service_id, crash_id, call.cmd_id, i, call_config.sleep
        )
        for j, arg in enumerate(call.args):
            crash_db.insert_callarg(
                connection,
                call_id,
                j,
                arg.argtype,
                arg.get_db_data(),
                arg.get_info(),
            )


def insert_update_service(connection, service):
    return interface_db.insert_update_service(connection, service)


def get_service(connection, service_name, device, real_device_id=None):
    return interface_db.get_service(connection, service_name, device, real_device_id)


def insert_update_binderfunc(
    connection,
    service_id,
    binder_func_type,
    mangled_symbol,
    demangled_symbol,
    offset,
):
    return binderfunc_db.insert_update_binderfunc(
        connection,
        service_id,
        binder_func_type,
        mangled_symbol,
        demangled_symbol,
        offset,
    )


def get_binderfuncs(connection, service_id):
    return binderfunc_db.get_binderfuncs(connection, service_id)


def clear_binderfunc(connection, service_id):
    return binderfunc_db.clear_binderfunc(connection, service_id)


def dump_used_deser(connection, service_id):
    binderfuncs = get_binderfuncs(connection, service_id)
    tmp = tempfile.mktemp()
    binderfuncs = list(set(f["functype"] for f in binderfuncs))
    open(tmp, "w+").write("\n".join(binderfuncs))
    return tmp


def get_used_deser_mangled(connection, service_id):
    binderfuncs = get_binderfuncs(connection, service_id)
    binderfuncs = list(set(f["mangled"] for f in binderfuncs))
    return binderfuncs


def insert_phase2_seed(connection, service_id, cmd_id, interface):
    phase2_db.insert_phase2_seed(connection, service_id, cmd_id, interface)


def insert_apphandle(
    connection, service, device, can_get_handle, service_context
):
    service = get_service(connection, service, device)
    if service is None:
        return None
    db_id = service.db_id
    return app_handle.insert_apphandle(
        connection, db_id, can_get_handle, service_context
    )


def can_app_handle(connection, service, device):
    service = get_service(connection, service, device)
    if service is None:
        return None
    db_id = service.db_id
    out = app_handle.get_apphandle(connection, db_id)
    if out is None:
        return None
    return out["app_can_get_handle"]

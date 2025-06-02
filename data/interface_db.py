import sqlite3
import logging
import os
import sys
import traceback

basepath = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(basepath)

from service.service import Service 
from service.service import Service, Cmd, Arg
from instrument.lib import NativeFunction, onTransactFunction

def init_db(BINDER_DB):
    connection = sqlite3.connect(BINDER_DB)
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS service (
        id INTEGER PRIMARY KEY,
        device TEXT,
        service_name TEXT,
        binary_path TEXT,
        arch TEXT,
        is_app INTEGER,
        is_svcsvr INTEGER,
        is_native INTEGER,
        onTransact_bin TEXT,
        onTransact_entry INTEGER,
        onTransact_last INTEGER,
        onTransact_fname TEXT,
        onTransact_module TEXT,
        onTransact_interface TEXT,
        onTransact_md5 TEXT,
        onTransact_BBinder TEXT,
        cmd_ids_enumerated INTEGER,
        CONSTRAINT unqs UNIQUE (device, service_name)
    );
    """
    cursor.execute(create_table_query)
    create_table_query = """
    CREATE TABLE IF NOT EXISTS interface (
        id INTEGER PRIMARY KEY,
        service_id INTEGER,
        cmd_id INTEGER,
        valid INTEGER,
        args_enumerated INTEGER,
        FOREIGN KEY(service_id) REFERENCES service(id),
        CONSTRAINT unqi UNIQUE (service_id, cmd_id)
    );
    """
    cursor.execute(create_table_query)
    create_table_query = """
    CREATE TABLE IF NOT EXISTS args (
        id INTEGER PRIMARY KEY,
        interface_id INTEGER,
        ordering INTEGER,
        type TEXT,
        info TEXT,
        constr TEXT,
        FOREIGN KEY(interface_id) REFERENCES interface(id),
        CONSTRAINT unqa UNIQUE (interface_id, ordering)
    );
    """
    cursor.execute(create_table_query)
    cursor.close()
    connection.close()


def insert_arg(connection, interface_id, arg:Arg, order):
    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO args (interface_id, ordering, type, info, constr) 
            VALUES (?,?,?,?,?)
            """
        cursor.execute(insert_query, (interface_id, order, arg.argtype, "", ""))
        connection.commit()
        arg_id = cursor.lastrowid
        cursor.close()
        return arg_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting arg {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting arg {str(e)}, {traceback.format_exc()}') 


def insert_update_arg(connection, interface_id, arg:Arg, order):
    try:
        arg_existing = get_arg(connection, interface_id, order)
        if arg_existing is None:
            arg_id = insert_arg(connection, interface_id, order)
            return arg_id
        else:
            cursor = connection.cursor()
            update_query = """UPDATE arg SET interface_id = ?, 
                ordering = ?,
                type = ?, info = ?, constr = ?,
                where id = ?
                """
            cursor.execute(update_query, interface_id, order, 
                           arg.argtype, "", "", arg_existing.db_id)
            connection.commit()
            cursor.close()
            return arg.db_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed insert/update of service{str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed insert/update of service {str(e)}, {traceback.format_exc()}')

def get_arg(connection, interface_id, ordering):
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * from args WHERE interface_id = ? AND ordering = ?"
        cursor.execute(select_data_query, (interface_id, ordering, ))
        rows = cursor.fetchall()
        if len(rows) == 0:
            return None
        r = rows[0]
        a_id = r[0]
        ordering = r[1]
        argtype = r[2]
        return Arg(argtype, db_id=a_id)
    except Exception as e:
        logging.error(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}') 

def get_args(connection, interface_id):
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * from args WHERE interface_id = ? ORDER BY ordering"
        cursor.execute(select_data_query, (interface_id, ))
        rows = cursor.fetchall()
        args = []
        for r in rows:
            a_id = r[0]
            ordering = r[1]
            argtype = r[2]
            args.append(Arg(argtype, db_id=a_id))
        return args
    except Exception as e:
        logging.error(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}') 

def insert_interface(connection, service_id, interface:Cmd):
    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO interface (service_id, cmd_id, valid, args_enumerated) 
            VALUES (?,?,?,?)
            """
        cursor.execute(insert_query, (service_id, interface.cmd_id, int(interface.valid), int(interface.args_enumerated)))
        connection.commit()
        interface_id = cursor.lastrowid
        cursor.close()
        for i, arg in enumerate(interface.args):
            insert_arg(connection, interface_id, arg, i)
        return interface_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting interface {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting interface {str(e)}, {traceback.format_exc()}') 

def insert_update_interface(connection, service_id, interface:Cmd):
    try:
        interface_existing = get_interface(connection, service_id, interface.cmd_id)
        if interface_existing is None:
            interface_id = insert_interface(connection, service_id, interface)
            return interface_id
        else:
            cursor = connection.cursor()
            update_query = """UPDATE interface SET service_id = ?, 
                cmd_id = ?,
                valid = ?, args_enumerated = ? 
                where id = ?
                """
            cursor.execute(update_query, (service_id, interface.cmd_id, int(interface.valid), 
                           int(interface.args_enumerated), interface_existing.db_id))
            connection.commit()
            cursor.close()
            for arg in interface.args:
                insert_update_arg(connection, interface_existing.db_id, arg)
            return interface_existing.db_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed insert/update of service{str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed insert/update of service {str(e)}, {traceback.format_exc()}')

def get_interface(connection, service_id, cmd_id):
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * from interface WHERE service_id = ? AND cmd_id = ?"
        cursor.execute(select_data_query, (service_id, cmd_id,))
        rows = cursor.fetchall()
        if len(rows) == 0:
            return None
        r = rows[0]
        i_id = r[0]
        service_id = r[1]
        cmd_id = r[2]
        valid = r[3]
        enumerated = r[4]
        args = get_args(connection, i_id)
        return Cmd(cmd_id, args=args, db_id=i_id, valid=valid, args_enumerated=enumerated)
    except Exception as e:
        logging.error(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}')  

def get_interfaces(connection, service_id):
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * from interface WHERE service_id = ?"
        cursor.execute(select_data_query, (service_id, ))
        rows = cursor.fetchall()
        cmds = []
        for r in rows:
            i_id = r[0]
            service_id = r[1]
            cmd_id = r[2]
            valid = r[3]
            enumerated = r[4]
            args = get_args(connection, i_id)
            cmds.append(Cmd(cmd_id, args=args, db_id=i_id, valid=valid, args_enumerated=enumerated))
        return cmds
    except Exception as e:
        logging.error(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed retrieving  interface {str(e)}, {traceback.format_exc()}') 


def insert_service(connection, service:Service):
    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO service (device, service_name, binary_path, arch, is_app, 
            is_svcsvr, is_native, onTransact_bin, onTransact_entry, onTransact_last, 
            onTransact_fname, onTransact_module, onTransact_interface, onTransact_md5, onTransact_BBinder, cmd_ids_enumerated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """
        if service.onTransact is not None:
            onTransact_bin = service.onTransact.bin
            onTransact_entry_addr = service.onTransact.entry_addr
            onTransact_last_addr = service.onTransact.last_addr
            onTransact_fname = service.onTransact.fname
            onTransact_module = service.onTransact.module
            onTransact_interface = service.onTransact.interface
            onTransact_md5 = service.onTransact.md5
            onTransact_BBinder = service.onTransact.BBinder_path
        else:
            onTransact_bin = ""
            onTransact_entry_addr = -1
            onTransact_last_addr = -1
            onTransact_fname = ""
            onTransact_module = ""
            onTransact_interface = ""
            onTransact_md5 = ""
            onTransact_BBinder = ""
        cursor.execute(insert_query, (service.meta_device_id, service.service_name, service.binary_path, 
                                      service.arch, int(service.is_app), int(service.is_svcsvr), 
                                      int(service.is_native), onTransact_bin, onTransact_entry_addr, 
                                      onTransact_last_addr, onTransact_fname, onTransact_module, onTransact_interface, onTransact_md5, onTransact_BBinder, int(service.cmd_ids_enumerated)))
        connection.commit()
        service_id = cursor.lastrowid
        cursor.close()
        if service.cmds is not None:
            for cmd in service.cmds:
                insert_interface(connection, service_id, cmd)
        return service_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting service {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting service {str(e)}, {traceback.format_exc()}')
    

def insert_update_service(connection, service:Service):
    try:
        if service.onTransact is not None:
            onTransact_bin = service.onTransact.bin
            onTransact_entry_addr = service.onTransact.entry_addr
            onTransact_last_addr = service.onTransact.last_addr
            onTransact_fname = service.onTransact.fname
            onTransact_module = service.onTransact.module
            onTransact_interface = service.onTransact.interface
            onTransact_md5 = service.onTransact.md5
            onTransact_BBinder = service.onTransact.BBinder_path
        else:
            onTransact_bin = ""
            onTransact_entry_addr = -1
            onTransact_last_addr = -1
            onTransact_fname = ""
            onTransact_module = ""
            onTransact_interface = ""
            onTransact_md5 = ""
            onTransact_BBinder = ""
        svc_exising = get_service(connection, service.service_name, service.meta_device_id)
        if svc_exising is None:
            service_id = insert_service(connection, service)
            return service_id
        else:
            cursor = connection.cursor()
            update_query = """UPDATE service SET binary_path = ?, arch = ?,
                is_app = ?, is_svcsvr = ?, is_native = ?, 
                onTransact_bin = ?, onTransact_entry = ?,
                onTransact_last = ?, onTransact_fname = ?,
                onTransact_module = ?, onTransact_interface = ?, onTransact_md5 = ?, onTransact_BBinder = ?, cmd_ids_enumerated = ? 
                where id = ?
                """
            cursor.execute(update_query, (service.binary_path, 
                                      service.arch, int(service.is_app), int(service.is_svcsvr), 
                                      int(service.is_native), onTransact_bin, onTransact_entry_addr, 
                                      onTransact_last_addr, onTransact_fname, onTransact_module, onTransact_interface, onTransact_md5, onTransact_BBinder, 
                                      int(service.cmd_ids_enumerated), svc_exising.db_id))
            connection.commit()
            cursor.close()
            if service.cmds is not None:
                for cmd in service.cmds:
                    insert_update_interface(connection, svc_exising.db_id, cmd)
            return svc_exising.db_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed insert/update of service{str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed insert/update of service {str(e)}, {traceback.format_exc()}')


def get_service(connection, service_name, device, real_device_id=None):
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * from service WHERE service_name = ? AND device = ?"
        cursor.execute(select_data_query, (service_name, device, ))
        rows = cursor.fetchall()
        if len(rows) == 0:
            return None
        assert len(rows) == 1, f"[BINDERDB] nr of services > 1: {service_name},{device}"
        r = rows[0]
        db_id = r[0]
        device = r[1]
        service_name = r[2]
        binary_path = r[3]
        arch = r[4]
        is_app = bool(r[5])
        is_svcsvr = bool(r[6])
        is_native = bool(r[7])
        onTransact_bin = r[8]
        onTransact_entry = int(r[9])
        onTransact_last = int(r[10])
        onTransact_fname = r[11]
        onTransact_module = r[12]
        onTransact_interface = r[13]
        onTransact_md5 = r[14]
        onTransact_BBinder = r[15]
        enumerated = r[16]
        if onTransact_bin == "" and onTransact_entry == -1 and onTransact_last == -1 and onTransact_fname == "":
            onTransact = None
        else:
            onTransact = onTransactFunction(onTransact_entry, onTransact_last, onTransact_fname, 
                                        onTransact_fname, onTransact_bin, onTransact_module, onTransact_interface, onTransact_md5, onTransact_BBinder)
        if real_device_id is None:
            svc = Service(service_name, device, arch=arch, binary_path=binary_path, is_app=is_app, 
                       is_svcsvr=is_svcsvr, is_native=is_native, onTransact=onTransact, db_id=db_id,
                       cmd_ids_enumerated=enumerated)
        else:
            svc = Service(service_name, real_device_id, arch=arch, binary_path=binary_path, is_app=is_app, 
                       is_svcsvr=is_svcsvr, is_native=is_native, onTransact=onTransact, db_id=db_id,
                       cmd_ids_enumerated=enumerated, meta_device_id=device)
        cmds = get_interfaces(connection, svc.db_id) 
        svc.cmds = cmds
        return svc
    except Exception as e:
        logging.error(f'[BINDERDB] Failed retrieving  service {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed retrieving  service {str(e)}, {traceback.format_exc()}')

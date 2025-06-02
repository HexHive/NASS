import sqlite3
import logging
import os
import sys
import traceback

basepath = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(basepath)

from service.bdsm import BDSM 
from service.service import Service, Cmd, Arg
from instrument.lib import Call, CallConfig

def init_db(BINDER_DB):
    connection = sqlite3.connect(BINDER_DB)
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS crash (
        id INTEGER PRIMARY KEY,
        service_id INTEGER,
        info TEXT,
        FOREIGN KEY(service_id) REFERENCES service(id)
    );
    """
    cursor.execute(create_table_query)
    create_table_query = """
    CREATE TABLE IF NOT EXISTS call (
        id INTEGER PRIMARY KEY,
        service_id INTEGER,
        crash_id INTEGER,
        cmd_id INTEGER,
        ordering INTEGER,
        sleep INTEGER,
        FOREIGN KEY(service_id) REFERENCES service(id),
        FOREIGN KEY(crash_id) REFERENCES crash(id)
    );
    """
    cursor.execute(create_table_query)
    create_table_query = """
    CREATE TABLE IF NOT EXISTS callarg (
        id INTEGER PRIMARY KEY,
        call_id INTEGER,
        ordering INTEGER,
        type TEXT,
        data TEXT,
        info TEXT,
        FOREIGN KEY(call_id) REFERENCES call(id)
    );
    """
    cursor.execute(create_table_query)
    cursor.close()
    connection.close()

def insert_crash(connection, service_id, info=""):
    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO crash (service_id, info) 
            VALUES (?,?)
            """
        cursor.execute(insert_query, (service_id,info))
        connection.commit()
        crash_id = cursor.lastrowid
        cursor.close()
        return crash_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting crash {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting crash {str(e)}, {traceback.format_exc()}') 

def insert_call(connection, service_id, crash_id, cmd_id, ordering, sleep):
    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO call (service_id, crash_id, cmd_id, ordering, sleep) 
            VALUES (?,?,?,?,?)
            """
        cursor.execute(insert_query, (service_id, crash_id, cmd_id, ordering, sleep))
        connection.commit()
        call_id = cursor.lastrowid
        cursor.close()
        return call_id 
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting call {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting call {str(e)}, {traceback.format_exc()}') 

def insert_callarg(connection, call_id, ordering, type, data, info):
    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO callarg (call_id, ordering, type, data, info) 
            VALUES (?,?,?,?,?)
            """
        cursor.execute(insert_query, (call_id, ordering, type, data, info))
        connection.commit()
        callarg_id = cursor.lastrowid
        cursor.close()
        return callarg_id 
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting callarg {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting callarg {str(e)}, {traceback.format_exc()}') 


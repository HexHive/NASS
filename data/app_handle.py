import sqlite3
import logging
import os
import sys
import traceback

basepath = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(os.path.join(basepath, ".."))

"""
Table to store information on the selinux check that is done 
in the service manager
"""

def init_db(BINDER_DB):
    connection = sqlite3.connect(BINDER_DB)
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS apphandle (
        id INTEGER PRIMARY KEY,
        app_can_get_handle BOOL,
        service_context TEXT,
        service_id INTEGER,
        FOREIGN KEY(service_id) REFERENCES service(id)
    );
    """
    cursor.execute(create_table_query)
    cursor.close()
    connection.close()


def get_apphandle(connection, service_id):
    # return a list of json seeds
    cursor = connection.cursor()
    select_data_query = "SELECT * from apphandle WHERE service_id = ?"
    cursor.execute(select_data_query, (service_id, ))
    rows = cursor.fetchall()
    if len(rows) == 0:
        return None
    r = rows[0]
    out = {"id": r[0], "service_context": r[2], "app_can_get_handle": r[1], "service_id": r[3]} 
    return out

def update_apphandle(connection, db_id, service_id, can_get_handle, service_context):
    try:
        cursor = connection.cursor()
        update_query = """UPDATE apphandle SET service_id = ?, 
            app_can_get_handle = ?,
            service_context = ? 
            where id = ?
            """
        cursor.execute(update_query, (service_id, can_get_handle, service_context, db_id,))
        connection.commit()
        cursor.close()
        return db_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed insert/update of apphandle{str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed insert/update of apphandle {str(e)}, {traceback.format_exc()}')


def insert_apphandle(connection, service_id, can_get_handle, service_context, replace=True):
    try:
        if replace:
            # check if exists
            existing = get_apphandle(connection, service_id)
            if existing is not None:
                return update_apphandle(connection, existing["id"], service_id, service_context, can_get_handle) 
            #TODO: what to do in this case, now just insert interface
            insert_apphandle(connection, service_id, can_get_handle, service_context, replace=False) 
        else:
            cursor = connection.cursor()
            insert_query = """
                INSERT INTO apphandle (app_can_get_handle, service_context, service_id) 
                VALUES (?,?,?)
                """
            cursor.execute(insert_query, (can_get_handle, service_context, service_id))
            connection.commit()
            apphandle_id = cursor.lastrowid
            cursor.close()
            return apphandle_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting apphandle {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting apphandle {str(e)}, {traceback.format_exc()}') 
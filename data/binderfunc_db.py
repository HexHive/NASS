import sqlite3
import logging
import os
import sys
import traceback

basepath = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(os.path.join(basepath, ".."))

def init_db(BINDER_DB):
    connection = sqlite3.connect(BINDER_DB)
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS binderfunc (
        id INTEGER PRIMARY KEY,
        functype TEXT,
        mangled TEXT,
        demangled TEXT,
        offset INTEGER,
        service_id INTEGER,
        FOREIGN KEY(service_id) REFERENCES service(id)
    );
    """
    cursor.execute(create_table_query)
    cursor.close()
    connection.close()

def insert_binderfunc(connection, service_id, binder_func_type, 
                        mangled_symbol, demangled_symbol, offset):
    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO binderfunc (functype, mangled, demangled, offset, service_id) 
            VALUES (?,?,?,?,?)
            """
        cursor.execute(insert_query, (binder_func_type, mangled_symbol, demangled_symbol, offset, 
                                      service_id))
        connection.commit()
        interface_id = cursor.lastrowid
        cursor.close()
        return interface_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting binderfunc {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting binderfunc {str(e)}, {traceback.format_exc()}') 

def insert_update_binderfunc(connection, service_id, binder_func_type, 
                            mangled_symbol, demangled_symbol, offset):
    try:
        binderfunc_existing = get_binderfunc_by_mangled(connection, service_id, mangled_symbol)
        if binderfunc_existing is None:
            binderfunc_id = insert_binderfunc(connection, service_id, binder_func_type, 
                            mangled_symbol, demangled_symbol, offset)
            return binderfunc_id 
        else:
            cursor = connection.cursor()
            update_query = """UPDATE binderfunc SET functype = ?, 
                mangled = ?,
                demangled = ?, offset = ?, service_id = ?
                where id = ?
                """
            cursor.execute(update_query, (binder_func_type, mangled_symbol, 
                                          demangled_symbol, offset, service_id, binderfunc_existing["id"]))
            connection.commit()
            cursor.close()
            return binderfunc_existing["id"]
    except Exception as e:
        logging.error(f'[BINDERDB] Failed insert/update of binderfunc {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed insert/update of binderfunc {str(e)}, {traceback.format_exc()}')

def get_binderfunc_by_mangled(connection, service_id, mangled):
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * from binderfunc WHERE service_id = ? AND mangled = ?"
        cursor.execute(select_data_query, (service_id, mangled,))
        rows = cursor.fetchall()
        if len(rows) == 0:
            return None
        r = rows[0]
        bf_id = r[0]
        functype = r[1]
        mangled = r[2]
        demangled = r[3]
        offset = r[4]
        return {"id": bf_id, "functype": functype, "mangled": mangled, "demangled": demangled, "offset": offset} 
    except Exception as e:
        logging.error(f'[BINDERDB] Failed retrieving  binderfunc {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed retrieving  binderfunc {str(e)}, {traceback.format_exc()}')  

def get_binderfuncs(connection, service_id):
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * from binderfunc WHERE service_id = ?"
        cursor.execute(select_data_query, (service_id, ))
        rows = cursor.fetchall()
        funcs = []
        for r in rows:
            bf_id = r[0]
            functype = r[1]
            mangled = r[2]
            demangled = r[3]
            offset = r[4]
            funcs.append({"id": bf_id, "functype": functype, "mangled": mangled, "demangled": demangled, "offset": offset})
        return funcs 
    except Exception as e:
        logging.error(f'[BINDERDB] Failed retrieving binderfunc {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed retrieving binderfunc {str(e)}, {traceback.format_exc()}') 
  
def clear_binderfunc(connection, service_id):
    try:
        cursor = connection.cursor()
        select_data_query = "DELETE from binderfunc WHERE service_id = ?"
        cursor.execute(select_data_query, (service_id, ))
        connection.commit()
        cursor.close()
    except Exception as e:
        logging.error(f'[BINDERDB] Failed deleting binderfunc {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed deleting binderfunc {str(e)}, {traceback.format_exc()}')  
import sqlite3
import logging
import json
import traceback

def init_db(BINDER_DB):
    connection = sqlite3.connect(BINDER_DB)
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS phase2_seeds (
        id INTEGER PRIMARY KEY,
        service_id INTEGER,
        cmd_id INTEGER,
        interface TEXT,
        FOREIGN KEY(service_id) REFERENCES service(id)
    );
    """
    cursor.execute(create_table_query)
    cursor.close()
    connection.close()

def get_phase2_seed(connection, service_id, cmd_id):
    # return a list of json seeds
    cursor = connection.cursor()
    select_data_query = "SELECT * from phase2_seeds WHERE service_id = ? AND cmd_id = ?"
    cursor.execute(select_data_query, (service_id, cmd_id, ))
    rows = cursor.fetchall()
    if len(rows) == 0:
        return []
    out = []
    for r in rows:
        db_id = r[0]
        s_id = r[1]
        cd = r[2]
        int_json = json.loads(r[3])
        out.append((db_id, s_id,cd,int_json))
    return out

def update_phase2_seed(connection, db_id, service_id, cmd_id, interface):
    try:
        cursor = connection.cursor()
        update_query = """UPDATE phase2_seeds SET service_id = ?, 
            cmd_id = ?,
            interface = ?
            where id = ?
            """
        cursor.execute(update_query, (service_id, cmd_id, json.dumps(interface), db_id,))
        connection.commit()
        cursor.close()
        return db_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed insert/update of service{str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed insert/update of service {str(e)}, {traceback.format_exc()}')


def insert_phase2_seed(connection, service_id, cmd_id, interface, replace=True):
    try:
        if replace:
            # check if exists
            existing = get_phase2_seed(connection, service_id, cmd_id)
            if len(existing) == 1:
                return update_phase2_seed(connection, existing[0][0], service_id, cmd_id, interface) 
            #TODO: what to do in this case, now just insert interface
            insert_phase2_seed(connection, service_id, cmd_id, interface, replace=False) 
        else:
            cursor = connection.cursor()
            insert_query = """
                INSERT INTO phase2_seeds (service_id, cmd_id, interface) 
                VALUES (?,?,?)
                """
            cursor.execute(insert_query, (service_id, cmd_id, json.dumps(interface)))
            connection.commit()
            interface_db_id = cursor.lastrowid
            cursor.close()
            return interface_db_id
    except Exception as e:
        logging.error(f'[BINDERDB] Failed inserting phase_2 interface {str(e)}, {traceback.format_exc()}')
        print(f'[BINDERDB] Failed inserting phase_2 interface {str(e)}, {traceback.format_exc()}') 
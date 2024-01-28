import pypyodbc as odbc
from dotenv import load_dotenv
import os

load_dotenv()


def connect_to_database():
    """
        Connect to Azure database
    """
    server = os.environ.get('DB_SERVER')
    database = os.environ.get('DB_DATABASE')
    username = os.environ.get('DB_USERNAME')
    password = os.environ.get('DB_PASSWORD')

    connection_string = f'Driver={{ODBC Driver 18 for SQL Server}};Server=tcp:{server},1433;Database={database};Uid={username};Pwd={password};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=86400;'

    return odbc.connect(connection_string)


def update_login_attempts(cursor, ip, now):
    """
    Update login attempts in the database.
    """
    sql_query = """
        MERGE INTO login_attempts AS target
        USING (VALUES (?, ?)) AS source(ip_address, [date])
        ON target.ip_address = source.ip_address
        WHEN MATCHED THEN
            UPDATE SET attempts_left = target.attempts_left - 1, [date] = source.[date]
        WHEN NOT MATCHED THEN
            INSERT (ip_address, [date], attempts_left) VALUES (source.ip_address, source.[date], 3);
    """
    cursor.execute(sql_query, (ip, str(now)))

import pypyodbc as odbc
from dotenv import load_dotenv
import os

load_dotenv()


def connect_to_database():
    server = os.environ.get('DB_SERVER')
    database = os.environ.get('DB_DATABASE')
    username = os.environ.get('DB_USERNAME')
    password = os.environ.get('DB_PASSWORD')

    connection_string = f'Driver={{ODBC Driver 18 for SQL Server}};Server=tcp:{server},1433;Database={database};Uid={username};Pwd={password};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=120;'

    return odbc.connect(connection_string)

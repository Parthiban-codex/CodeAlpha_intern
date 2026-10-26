import pymysql
import os
from dotenv import load_dotenv
load_dotenv()
c =pymysql.connect(
    host=os.getenv("aws-host"),
    user=os.getenv("aws-user"),
    password=os.getenv("aws-pass"),
    database=os.getenv("aws-db"),
    port=3306
)
print("db connected sucessfully")
c.close()
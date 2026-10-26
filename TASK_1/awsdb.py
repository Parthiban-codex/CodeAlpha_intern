import pymysql
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request

load_dotenv()
app = Flask(__name__)

def create_database():
    db_name = os.getenv("aws-db", "myapp")
    connection = pymysql.connect(
        host=os.getenv("aws-host"),
        user=os.getenv("aws-user"),
        password=os.getenv("aws-pass"),
        port=3306
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
        connection.commit()
    finally:
        connection.close()

create_database()

def get_connection():
    return pymysql.connect(
        host=os.getenv("aws-host"),
        user=os.getenv("aws-user"),
        password=os.getenv("aws-pass"),
        database=os.getenv("aws-db"),
        port=3306
    )

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/submit", methods=["POST"])
def register():
    name = request.form["name"]
    email = request.form["email"]
    password = request.form["password"]

    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `Register` (
                    `Name` VARCHAR(10),
                    `email` VARCHAR(30) UNIQUE,
                    `password` VARCHAR(20)
                )
            """)
            cursor.execute(
                "SELECT * FROM `Register` WHERE `email` = %s",
                (email,)
            )
            if cursor.fetchone():
                return "<h3>Warning! This email already exists.</h3>"
            
            cursor.execute("""
                INSERT INTO `Register` (`Name`, `email`, `password`)
                VALUES (%s, %s, %s)
            """, (name, email, password))

        connection.commit()
        return "<h3>Registration Successful!</h3>"

    finally:
        connection.close()

if __name__ == "__main__":
    app.run(debug=True)
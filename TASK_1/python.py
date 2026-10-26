from flask import Flask, render_template, request
import mysql.connector

obj = Flask(__name__)

def reg():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="parthiban",
        database="task1"
    )

@obj.route("/")
def t():
    return render_template("index.html")

@obj.route("/submit", methods=["POST"])
def m():
    name = request.form["name"]
    email = request.form["email"].lower()
    password = request.form["password"]
    
    l = reg()
    cursor = l.cursor()
    try:
        sql = "INSERT INTO register(name, email, password) VALUES (%s, %s, %s)"
        cursor.execute(sql, (name, email, password))
        l.commit()
        return "new row added.."
        
    except mysql.connector.Error as err:
        if err.errno == 1062: 
            return "This email is already registered in db"
        return f"Database Error: {err}"
        
    finally:
        cursor.close()
        l.close()
if __name__ == "__main__":
    obj.run(debug=True)
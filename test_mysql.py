import mysql.connector

connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="ai_fake_email_detector"
)

print("MySQL connected successfully!")

connection.close()
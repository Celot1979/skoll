import os
import sqlite3

# Fuga de secretos (bad practice)
API_KEY_SECRET = "AIzaSyD-1234567890-ABCDEF"

def buscar_usuario(nombre):
    # Vulnerabilidad lógica: Inyección SQL
    conn = sqlite3.connect("usuarios.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM usuarios WHERE nombre = '{nombre}'"
    cursor.execute(query)
    return cursor.fetchall()

def ejecutar_comando(cmd):
    # Vulnerabilidad de inyección de comandos
    os.system(cmd)

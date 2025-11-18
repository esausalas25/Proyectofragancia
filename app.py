from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors

# 🔐 Passlib para encriptar contraseñas
from passlib.hash import pbkdf2_sha256

# ================== HELPERS PARA CONTRASEÑAS ==================
def hash_password(password: str) -> str:
    """Devuelve el hash PBKDF2 de la contraseña."""
    return pbkdf2_sha256.hash(password)

def verify_password(raw_password: str, stored_password: str) -> bool:
    """
    Verifica la contraseña comparando con el hash almacenado.
    Si el valor almacenado no es un hash válido, hace comparación directa
    (compatibilidad con usuarios antiguos en texto plano).
    """
    try:
        return pbkdf2_sha256.verify(raw_password, stored_password)
    except ValueError:
        # No era un hash válido, comparamos como texto plano
        return raw_password == stored_password

# ================== FLASK & MySQL ==================
app = Flask(__name__, template_folder="templates")
app.secret_key = '09f78ead-8a13-11f0-9f04-089798bc6dda'  # cambia por una clave segura

app.config['MYSQL_HOST'] = 'b7si4ds7m59urowspuir-mysql.services.clever-cloud.com'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_USER'] = 'uadou1jkge1jtyos'
app.config['MYSQL_PASSWORD'] = 'ENB0kFpgrVr9QOjkJXtI'
app.config['MYSQL_DB'] = 'b7si4ds7m59urowspuir'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # para que fetchone/fetchall devuelvan dicts

mysql = MySQL(app)

# ================== RUTAS BÁSICAS ==================
@app.route('/')
def inicio():
    return render_template("index.html")

@app.route('/contacto', methods=['GET', 'POST'])
def contacto():
    user = {'nombre': '', 'email': '', 'mensaje': ''}
    if request.method == 'GET':
        user['nombre'] = request.args.get('nombre', '')
        user['email'] = request.args.get('email', '')
        user['mensaje'] = request.args.get('mensaje', '')
    return render_template("contacto.html", usuario=user)

@app.route('/contactopost', methods=['GET', 'POST'])
def contactopost():
    user = {'nombre': '', 'email': '', 'mensaje': ''}
    if request.method == 'POST':
        user['nombre'] = request.form.get('nombre', '')
        user['email'] = request.form.get('email', '')
        user['mensaje'] = request.form.get('mensaje', '')
        flash("✅ ¡Mensaje enviado correctamente!", "success")
        return redirect(url_for('contactopost'))
    return render_template("contactopost.html", usuario=user)

# ================== AUTENTICACIÓN ==================
@app.route('/login', methods=['GET'])
def login():
    return render_template("login.html")

@app.route('/accesologin', methods=['POST'])
def accesologin():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()

    cur = mysql.connection.cursor()
    # Ahora obtenemos solo por email, y la contraseña la verificamos en Python
    cur.execute("SELECT * FROM usuario WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close()

    if user and verify_password(password, user['password']):
        session['usuario'] = user['email']
        session['nombre'] = user.get('nombre') or ''
        session['rol'] = user.get('id_rol', 2)

        if user['id_rol'] == 1:
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('inicio'))
    else:
        flash('Usuario y Contraseña incorrecta', 'error')
        return redirect(url_for('login'))

@app.route('/Registro', methods=['GET', 'POST'])
def Registro():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        id_rol = 2  # usuario por defecto

        if not nombre or not email or not password:
            flash("Completa nombre, correo y contraseña.", "warning")
            return render_template("Registro.html")

        cur = mysql.connection.cursor()
        # evita duplicado de email
        cur.execute("SELECT id FROM usuario WHERE email=%s", (email,))
        exists = cur.fetchone()
        if exists:
            cur.close()
            flash("Ese correo ya está registrado.", "warning")
            return render_template("Registro.html")

        # 🔐 Guardar contraseña encriptada
        hashed_password = hash_password(password)

        cur.execute(
            "INSERT INTO usuario (email, nombre, password, id_rol) VALUES (%s, %s, %s, %s)",
            (email, nombre, hashed_password, id_rol)
        )
        mysql.connection.commit()
        cur.close()

        flash("Registro exitoso. Ahora puedes iniciar sesión.", "success")
        return redirect(url_for('login'))

    return render_template("Registro.html")

@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for('inicio'))

# ================== PÁGINAS CON SESIÓN ==================
@app.route('/usuario')
def usuario():
    if 'usuario' in session:
        return render_template("usuario.html", usuario=session['usuario'])
    else:
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'usuario' in session and session.get('rol') == 1:
        return render_template("admin.html", usuario=session['usuario'])
    else:
        flash('Acceso restringido.', 'error')
        return redirect(url_for('login'))

# ================== CRUD USUARIOS ==================
@app.route('/listar', methods=['GET', 'POST'])
def listar():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    # ---- AGREGAR USUARIO ----
    if request.method == 'POST' and 'agregar_usuario' in request.form:
        nombre = request.form['nombre'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        id_rol = 2

        if not nombre or not email or not password:
            flash("Completa los campos.", "warning")
        else:
            # 🔐 Encriptar contraseña antes de guardar
            hashed_password = hash_password(password)

            cur.execute(
                "INSERT INTO usuario (nombre, email, password, id_rol) VALUES (%s, %s, %s, %s)",
                (nombre, email, hashed_password, id_rol)
            )
            mysql.connection.commit()
            flash("Usuario agregado correctamente!", "success")
        cur.close()
        return redirect(url_for('listar'))

    # ---- EDITAR USUARIO ----
    elif request.method == 'POST' and 'editar_usuario' in request.form:
        user_id = request.form['id']
        nombre = request.form['nombre'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        # Si el campo contraseña viene vacío, no la cambiamos
        if password:
            new_password = hash_password(password)
            cur.execute(
                "UPDATE usuario SET nombre=%s, email=%s, password=%s WHERE id=%s",
                (nombre, email, new_password, user_id)
            )
        else:
            cur.execute(
                "UPDATE usuario SET nombre=%s, email=%s WHERE id=%s",
                (nombre, email, user_id)
            )

        mysql.connection.commit()
        cur.close()
        flash("Usuario actualizado correctamente!", "success")
        return redirect(url_for('listar'))

    # ---- ELIMINAR USUARIO (vía querystring) ----
    if request.args.get('eliminar_usuario'):
        user_id = request.args.get('eliminar_usuario')
        cur.execute("DELETE FROM usuario WHERE id = %s", (user_id,))
        mysql.connection.commit()
        cur.close()
        flash("Usuario eliminado correctamente!", "danger")
        return redirect(url_for('listar'))

    # ---- LISTAR USUARIOS ----
    cur.execute("SELECT * FROM usuario ORDER BY id ASC")
    usuarios = cur.fetchall()
    cur.close()

    return render_template(
        "editar_usuario.html",
        usuario=session['usuario'],
        usuarios=usuarios
    )

# ---- ELIMINAR USUARIO (POST limpio para usar con <form>) ----
@app.route('/usuarios/<int:id>/borrar', methods=['POST'])
def borrar_usuario(id):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    # Evita borrarte a ti mismo
    cur = mysql.connection.cursor()
    cur.execute("SELECT email FROM usuario WHERE id = %s", (id,))
    row = cur.fetchone()
    if row and row['email'] == session.get('usuario'):
        cur.close()
        flash("No puedes eliminar tu propio usuario activo.", "warning")
        return redirect(url_for('listar'))

    cur.execute("DELETE FROM usuario WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    flash("Usuario eliminado.", "success")
    return redirect(url_for('listar'))

# ================== CRUD PRODUCTOS ==================
@app.route('/agregar_producto', methods=['GET', 'POST'])
def agregar_producto():
    if request.method == 'POST':
        nombre = request.form['nombre'].strip()
        precio = float(request.form['precio'])
        descripcion = request.form['descripcion'].strip()

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO productos (nombre, precio, descripcion)
            VALUES (%s, %s, %s)
        """, (nombre, precio, descripcion))
        mysql.connection.commit()
        cur.close()

        flash('Producto agregado correctamente!', 'success')
        return redirect(url_for('agregar_producto'))

    # Mostrar productos
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM productos ORDER BY id DESC")
    productos = cur.fetchall()
    cur.close()

    return render_template('Agregar_productos.html', productos=productos)

@app.route('/listar_productos_agregados')
def listar_productos_agregados():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM productos ORDER BY id DESC")
    productos = cur.fetchall()
    cur.close()
    # Reutiliza el mismo template
    return render_template('Agregar_productos.html', productos=productos)

@app.route('/listar_productos')
def listar_productos():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM productos ORDER BY id DESC")
    productos = cur.fetchall()
    cur.close()
    return render_template("listar_productos.html", usuario=session['usuario'], productos=productos)

# Editar / Eliminar (POST) - VERSIÓN ORIGINAL
@app.route('/editar_producto/<int:id>', methods=['POST'])
def editar_producto(id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM productos WHERE id = %s", (id,))
    producto = cur.fetchone()

    if not producto:
        cur.close()
        flash("Producto no encontrado", "warning")
        return redirect(url_for('listar_productos'))

    accion = request.form.get('accion')

    if accion == 'eliminar':
        cur.execute("DELETE FROM productos WHERE id = %s", (id,))
        mysql.connection.commit()
        cur.close()
        flash("Producto eliminado correctamente!", "success")
        return redirect(url_for('listar_productos'))

    # actualizar
    nombre = request.form['nombre'].strip()
    precio = float(request.form['precio'])
    descripcion = request.form['descripcion'].strip()

    cur.execute("""
        UPDATE productos
        SET nombre=%s, precio=%s, descripcion=%s
        WHERE id=%s
    """, (nombre, precio, descripcion, id))
    mysql.connection.commit()
    cur.close()

    flash("Producto actualizado correctamente!", "success")
    return redirect(url_for('listar_productos'))

# Eliminar (GET simple — útil para enlaces rápidos)
@app.route('/eliminar_producto/<int:id>')
def eliminar_producto(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM productos WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    flash('Producto eliminado correctamente!', 'success')
    return redirect(url_for('listar_productos_agregados'))

# ================== OTRAS ==================
@app.route('/acercade')
def acercade():
    return render_template("acercade.html")

# ================== MAIN ==================
if __name__ == '__main__':
    app.run(debug=True, port=8000)

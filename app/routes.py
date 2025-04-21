from flask import Blueprint, request, jsonify, render_template, redirect, session, url_for
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from app import mongo
from pymongo.errors import DuplicateKeyError


app = Blueprint('main', __name__)


@app.route('/')
def home():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    user = mongo.db.usuarios.find_one({'usuario': data['usuario']})
    if user and check_password_hash(user['password'], data['password']):
        session['usuario'] = user['usuario']
        session['rol'] = user['rol']
        return redirect('/admin' if user['rol'] == 'admin' else '/eventos')
    return "Credenciales inválidas"


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/registro', methods=['POST'])
def registro():
    data = request.form
    if mongo.db.usuarios.find_one({'usuario': data['usuario']}):
        return "Usuario ya existe"
    nuevo = {
        "usuario": data['usuario'],
        "password": generate_password_hash(data['password']),
        "rol": data.get('rol', 'estudiante')
    }
    try:
        mongo.db.usuarios.insert_one(nuevo)
    except DuplicateKeyError:
        return "El nombre de usuario ya está en uso. Por favor elige otro."

    return redirect('/')


@app.route('/admin')
def admin():
    if session.get('rol') != 'admin':
        return redirect('/')
    eventos = mongo.db.eventos.find()
    return render_template('admin_panel.html', eventos=eventos)


@app.route('/eventos')
def ver_eventos():
    eventos = mongo.db.eventos.find()
    return render_template('eventos.html', eventos=eventos)


@app.route('/crear', methods=['POST'])
def crear_evento():
    if session.get('rol') != 'admin':
        return "No autorizado"
    evento = {
        "nombre": request.form['nombre'],
        "descripcion": request.form['descripcion'],
        "fecha": request.form['fecha'],
        "hora": request.form['hora'],
        "lugar": request.form['lugar'],
        "tipo": request.form['tipo'],
        "usuarios_registrados": []  # Inicia la lista de usuarios registrados
    }
    mongo.db.eventos.insert_one(evento)
    return redirect('/admin')


@app.route('/eliminar/<evento_id>')
def eliminar_evento(evento_id):
    if session.get('rol') != 'admin':
        return "No autorizado"
    mongo.db.eventos.delete_one({"_id": ObjectId(evento_id)})
    return redirect('/admin')


@app.route('/registrarse/<evento_id>')
def registrarse_evento(evento_id):
    if not session.get('usuario'):
        return redirect('/')

    # Obtener el evento y usuario
    evento = mongo.db.eventos.find_one({'_id': ObjectId(evento_id)})
    usuario = session['usuario']

    # Verificar si el usuario ya está registrado
    if usuario not in evento['usuarios_registrados']:
        # Registrar al usuario en el evento
        mongo.db.eventos.update_one(
            {'_id': ObjectId(evento_id)},
            {'$addToSet': {'usuarios_registrados': usuario}}
        )

        # Registrar el evento en el usuario (si deseas hacerlo en la colección de usuarios también)
        mongo.db.usuarios.update_one(
            {'usuario': usuario},
            {'$addToSet': {'eventos_registrados': evento_id}}
        )

    return redirect('/eventos')


@app.route('/quitar_registro/<evento_id>')
def quitar_registro(evento_id):
    if not session.get('usuario'):
        return redirect('/')

    usuario = session['usuario']

    # Obtener el evento
    evento = mongo.db.eventos.find_one({'_id': ObjectId(evento_id)})

    # Si el usuario está registrado, quitarlo
    if usuario in evento['usuarios_registrados']:
        mongo.db.eventos.update_one(
            {'_id': ObjectId(evento_id)},
            {'$pull': {'usuarios_registrados': usuario}}
        )

        # Quitar el evento del usuario (si es necesario)
        mongo.db.usuarios.update_one(
            {'usuario': usuario},
            {'$pull': {'eventos_registrados': evento_id}}
        )

    return redirect('/eventos')


@app.route('/ver_evento/<evento_id>')
def ver_evento(evento_id):
    if 'usuario' not in session:
        return redirect('/')

    evento = mongo.db.eventos.find_one({'_id': ObjectId(evento_id)})
    usuarios_registrados = []

    for usuario in evento.get('usuarios_registrados', []):
        usuario_data = mongo.db.usuarios.find_one({'usuario': usuario})
        if usuario_data:
            usuarios_registrados.append(usuario_data)

    ya_registrado = session['usuario'] in evento.get('usuarios_registrados', [])

    return render_template(
        'ver_evento.html',
        evento=evento,
        usuarios_registrados=usuarios_registrados,
        ya_registrado=ya_registrado
    )


@app.route('/editar_evento/<evento_id>', methods=['GET', 'POST'])
def editar_evento(evento_id):
    if 'usuario' not in session or session['usuario'] != 'admin':
        return redirect(url_for('home'))

    evento = mongo.db.eventos.find_one({'_id': ObjectId(evento_id)})

    if request.method == 'POST':
        nuevo_nombre = request.form['nombre']
        nueva_fecha = request.form['fecha']
        nueva_hora = request.form['hora']
        nuevo_tipo = request.form['tipo']
        nuevo_lugar = request.form['lugar']
        nueva_descripcion = request.form['descripcion']

        mongo.db.eventos.update_one(
            {'_id': ObjectId(evento_id)},
            {'$set': {
                'nombre': nuevo_nombre,
                'fecha': nueva_fecha,
                'hora': nueva_hora,
                'tipo': nuevo_tipo,
                'lugar': nuevo_lugar,
                'descripcion': nueva_descripcion
            }}
        )
        return redirect(url_for('main.admin'))

    return render_template('editar_evento.html', evento=evento)

mongo.db.usuarios.create_index('usuario', unique=True)

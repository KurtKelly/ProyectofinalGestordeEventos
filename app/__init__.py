from flask import Flask
from flask_pymongo import PyMongo

mongo = PyMongo()  # Instancia global


def create_app():
    app = Flask(__name__)
    app.config["MONGO_URI"] = "mongodb://localhost:27017/servicio_social"

    mongo.init_app(app)  # Aquí inicializas el mongo

    from app.routes import app as main_bp
    app.register_blueprint(main_bp)

    return app

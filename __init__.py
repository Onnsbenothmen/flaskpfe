from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate

app = Flask(__name__)
CORS(app)


# Configuration de l'URL de la base de données
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:postgres@localhost:5432/postgres"

# Initialisation de l'instance SQLAlchemy avec l'application Flask
db = SQLAlchemy(app)

# Initialisation de Flask-Migrate avec l'application Flask et l'instance SQLAlchemy
migrate = Migrate(app, db)

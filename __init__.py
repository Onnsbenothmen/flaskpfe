from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

db = SQLAlchemy()
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:postgres@localhost:5432/postgres"
#cors = CORS(app, resources={r"/": {"origins": "http://localhost:3000"}})
db.init_app(app)





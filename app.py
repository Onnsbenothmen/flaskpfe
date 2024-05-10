from flask_cors import CORS

from functools import wraps
from sqlalchemy.sql import func
from . import app, db
from .models import  Instance, Role
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
from datetime import datetime, timezone, timedelta
from werkzeug.utils import secure_filename
import os
from flask_mail import Mail, Message
from flask_jwt_extended import current_user, jwt_required, create_access_token, JWTManager, get_jwt_identity, get_jwt, create_refresh_token
import json
from flask import Flask, jsonify, request, make_response,redirect, url_for

from flask import Flask, jsonify, request, make_response, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from .models import  db,Users, ProgrammeVisite,Resultat

from flask_sqlalchemy import SQLAlchemy
import jwt
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from . import models
from . import app

from flask import request
from io import BytesIO
from tkinter import Canvas
from reportlab.pdfgen import canvas


from flask import send_file


from flask_cors import CORS


from sqlalchemy.orm import joinedload  # Importer joinedload depuis sqlalchemy.orm


# app = Flask(__name__)

CORS(app)
CORS(app, origins=["http://localhost:3000"])

# Définition du dossier de téléchargement des fichiers
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


jwt = JWTManager(app)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

# Génération d'une clé secrète aléatoire
secret_key = os.urandom(24).hex()
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']  # Configurez l'emplacement du jeton JWT
app.config['JWT_SECRET_KEY'] = secret_key  # Configurez la clé secrète JWT
# Configuration de l'application Flask avec la clé secrète



# app.config['SECRET_KEY'] = secret_key
# # Configuration de Flask-Mail avec vos coordonnées
# app.config['MAIL_SERVER'] = "smtp.googlemail.com"
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = "benothmenons09@gmail.com"
# app.config['MAIL_PASSWORD'] = "tvmg oqna uzjz etsf"
# app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'  # Adresse e-mail par défaut


app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:postgres@localhost:5432/postgres"

# Initialise la base de données
# db.init_app(app)

# Initialisation de Flask-Mail
# mail = Mail(app)

# Assurez-vous que le répertoire de téléchargement existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Liste des extensions de fichiers autorisées
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Fonction pour vérifier si l'extension du fichier est autorisée
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




# Fonction pour vérifier le token JWT dans les requêtes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return make_response(jsonify({'message': 'Token is missing'}), 401)
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(id=data['id']).first()
            if not current_user:
                return make_response(jsonify({'message': 'User not found'}), 404)
        except jwt.ExpiredSignatureError:
            return make_response(jsonify({'message': 'Token has expired'}), 401)
        except jwt.InvalidTokenError:
            return make_response(jsonify({'message': 'Token is invalid'}), 401)
        return f(current_user, *args, **kwargs)
    return decorated

# Fonction pour envoyer un e-mail d'inscription
def send_login_details(email, firstName, password, role_name):
    try:
        subject = 'Détails de connexion à notre application'
        message = f'Bonjour cher(e) {role_name}  {firstName},\n\nNous sommes ravis de vous accueillir sur notre plateforme ! Voici vos informations de connexion :\n\nEmail : {email}\nMot de passe : {password}\n\nConnectez-vous dès maintenant et commencez à explorer toutes les fonctionnalités offertes par notre application. Si vous avez des questions ou des commentaires, n\'hésitez pas à nous contacter. Nous sommes là pour vous aider !\n\nCordialement,\nL\'équipe de notre application'
        
        # Configuration du message
        msg = Message(subject, recipients=[email])
        msg.body = message

        # Envoi de l'e-mail
        mail.send(msg)
    except Exception as e:
        print("Erreur lors de l'envoi des informations de connexion par e-mail :", str(e))

# Route pour l'inscription d'un nouvel utilisateur
@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.form
        email = data.get("email")
        firstName = data.get("firstName")
        lastName = data.get("lastName")
        password = data.get("password")
        role_name = data.get("role")  # Récupérer le nom du rôle depuis la requête JSON
        

        # Recherche du rôle par son nom
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"message": "Rôle non trouvé"}), 404

   

        # Enregistrement des coordonnées de l'utilisateur dans la base de données
        new_user = Users(
            firstName=firstName,
            lastName=lastName,
            email=email,
            password=generate_password_hash(password),
            role_id=role.id,
            
        )
        db.session.add(new_user)
        db.session.commit()

        # Envoi d'un e-mail d'inscription à l'utilisateur
        send_login_details(email, firstName, password, role_name)

        # Retourner une réponse indiquant que l'utilisateur a été créé
        return jsonify({"message": "Utilisateur créé avec succès"}), 201
    except Exception as e:
        print("Erreur lors de l'inscription :", str(e))
        return jsonify({"error": f"Erreur lors de l'inscription : {str(e)}"}), 500

# Route de connexion

@app.route("/login", methods=["POST"])
def login():
    auth = request.json
    email = auth.get("email")  # Récupérer l'email de la requête
    password = auth.get("password")  # Récupérer le mot de passe de la requête

    # Recherche de l'utilisateur dans la base de données par son email
    user = Users.query.filter_by(email=email).first()
    if not user:
        return make_response({"message": "Utilisateur non trouvé"}, 404)

    # Vérification du mot de passe
    if check_password_hash(user.password, password):
        token_payload = {
            'id': user.id,
            'role': user.role.name if user.role else None,
            'email': user.email,
            'firstName': user.firstName,
            'lastName': user.lastName
        }
        token = create_access_token(identity=token_payload)  # Générer le token JWT

        # Retourner les informations du profil de l'utilisateur avec le token d'accès
        return jsonify({"token": token, "profile": token_payload}), 200
    else:
        # Si les identifiants ne correspondent pas, renvoyer un message d'erreur
        return make_response({'message': 'Veuillez vérifier vos identifiants'}, 401)

@app.route("/logout")
def logout():
    # Supprimer le cookie contenant le token JWT côté client
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('Authorization', '', expires=0)
    return resp

# Routes pour les tableaux de bord spécifiques
@app.route("/president_dashboard")
@token_required
def president_dashboard(current_user):
    if current_user.role.name != 'president':
        return make_response({'message': 'Permission denied'}, 403)
    # Logique pour le tableau de bord du président

@app.route("/admin_dashboard")
@token_required
def admin_dashboard(current_user):
    if current_user.role.name != 'adminPublique':
        return make_response({'message': 'Permission denied'}, 403)
    # Logique pour le tableau de bord de l'adminPublique


# ...

@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            return make_response({"message": f"User with id {user_id} not found"}, 404)

        # Mettre à jour les champs de l'utilisateur
        user.firstName = request.form.get('firstName')
        user.lastName = request.form.get('lastName')
        user.email = request.form.get('email')
        # Mettre à jour le rôle de l'utilisateur
        role_name = request.form.get('role_name')
        if role_name:
            # Vérifier si le rôle existe dans la base de données
            role = Role.query.filter_by(name=role_name).first()
            if role:
                user.role_id = role.id
            else:
                return make_response({"message": f"Role {role_name} not found"}, 404)

        # Vérifier si un fichier a été téléchargé dans la demande
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Mettre à jour le chemin de l'image de profil dans la base de données
                user.profile_image = filename

        db.session.commit()

        return jsonify({"message": "User updated successfully"}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to update user"}, 500)

@app.route('/profile/<conseiller_email>')
@jwt_required()
def my_profile(conseiller_email):
    current_user_email = get_jwt_identity()
    if conseiller_email != current_user_email:
        return jsonify({"error": "Unauthorized Access"}), 401
    
    user = Users.query.filter_by(email=conseiller_email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    response_body = {
        "id": user.id,
        "firstName": user.firstName,
        "lastName": user.lastName,
        "email": user.email,
        "phoneNumber": user.phoneNumber,
        "address": user.address,
        "profile_image": user.profile_image
    }
    return jsonify(response_body), 200

@app.route('/profiles', methods=['GET'])
@jwt_required()
def all_profiles():
    current_user_email = get_jwt_identity()
    
    users = Users.query.all()
    profiles = []
    
    for user in users:
        profile = {
            "id": user.id,
            "firstName": user.firstName,
            "lastName": user.lastName,
            "email": user.email,
            "phoneNumber": user.phoneNumber,
            "address": user.address,
            "profile_image": user.profile_image
        }
        profiles.append(profile)
    
    return jsonify(profiles), 200

@app.route('/user_profile')
def user_profile():
    # Récupérez les données de l'utilisateur depuis la base de données
    user = Users.query.filter_by(id=current_user).first()  # Assurez-vous de remplacer current_user_id par l'ID de l'utilisateur connecté

    # Renvoyez les données de l'utilisateur au format JSON
    return jsonify({
        "id": user.id,
        "firstName": user.firstName,
        "lastName": user.lastName,
        "email": user.email,
        "phoneNumber": user.phoneNumber,
        "address": user.address,
        "profile_image": user.profile_image
    })

@app.route('/update_profile/<int:user_id>', methods=['PUT'])
def update_profile(user_id):
    user = Users.query.get(user_id)
    if not user:
        os.abort(404, description=f"User with id {user_id} not found")

    formData = request.form

    for field in ['firstName', 'lastName', 'phoneNumber', 'address']:
        if field in formData:
            setattr(user, field, formData[field])

    # Check if an image is sent in the request
    if 'image' in request.files:
        image = request.files['image']
        if image.filename == '':
            return jsonify({"message": "No file selected for uploading"}), 400
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            user.profile_image = filename
            print(f"Image '{filename}' saved successfully in the database.")
        else:
            return jsonify({"message": "Allowed image types are png, jpg, jpeg, gif"}), 400

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        os.abort(500, description=str(e))

    response_body = {
        "id": user.id,
        "firstName": user.firstName,
        "lastName": user.lastName,
        "phoneNumber": user.phoneNumber,
        "address": user.address,
        "email": user.email,
        "profile_image": user.profile_image
    }

    return jsonify(response_body), 200



@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            return make_response({"message": f"User with id {user_id} not found"}, 404)

        db.session.delete(user)
        db.session.commit()

        return make_response({"message": "User deleted successfully"}, 200)

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": f"Unable to delete user: {str(e)}"}, 500)

@app.route("/addInstances", methods=["POST"])
def addInstance():
    data = request.json
    president_email = data.get("president_email")
    council_name = data.get("council_name")
    ville = data.get("ville")  # Récupérez la ville depuis les données JSON
    active = data.get("active")
    created_at = data.get("created_at")

    if president_email and council_name and ville:  # Assurez-vous que tous les champs requis sont présents
        instance = Instance.query.filter_by(president_email=president_email).first()
        if instance:
            return make_response({"message": "Instance already exists"}, 200)

        # Créez une nouvelle instance avec la ville
        new_instance = Instance(
            president_email=president_email,
            council_name=council_name,
            ville=ville,
            active=active if active is not None else True,
            created_at=created_at
        )
        db.session.add(new_instance)
        db.session.commit()
        return make_response({"message": "Instance Created"}, 201)

    return make_response({"message": "Missing required fields"}, 400)


@app.route("/instances", methods=["GET"])
def get_all_instances():
    try:
        instances = Instance.query.all()

        print("All Instances:", instances)

        serialized_instances = [instance.serialize() for instance in instances]  

        return jsonify({"data": serialized_instances}), 200

    except Exception as e:
        print(e)
        return make_response({"message": f"Error: {str(e)}"}, 500)


@app.route('/instances/<int:id>', methods=['PUT'])
def update_instance(id):
    instance = Instance.query.get_or_404(id)
    data = request.json
    instance.president_email = data.get('president_email', instance.president_email)
    instance.council_name = data.get('council_name', instance.council_name)
    instance.ville = data.get('ville', instance.ville)
    instance.active = data.get('active', instance.active)
    db.session.commit()
    return instance.serialize(), 200

@app.route("/instances/<int:instance_id>", methods=["DELETE"])
def delete_instance(instance_id):
    try:
        instance = Instance.query.get(instance_id)
        if not instance:
            return make_response({"message": f"Instance with id {instance_id} not found"}, 404)

        db.session.delete(instance)
        db.session.commit()

        return make_response({"message": "Instance deleted successfully"}, 200)

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": f"Unable to delete instance: {str(e)}"}, 500)


@app.route("/roles", methods=["POST"])
def create_role():
    try:
        data = request.json
        name = data.get("name")
        description = data.get("description")

        # Vérification si le nom du rôle est fourni
        if name:
            role = Role.query.filter_by(name=name).first()
            if role:
                return make_response({"message": "Le rôle existe déjà"}, 400)

            new_role = Role(name=name, description=description)
            db.session.add(new_role)
            db.session.commit()
            return make_response({"message": "Rôle créé avec succès"}, 201)
        else:
            # Si le nom du rôle n'est pas fourni, retourner un message d'erreur
            return make_response({"message": "Le nom du rôle est requis"}, 400)
    except Exception as e:
        # En cas d'erreur, retourner un message d'erreur avec le code de statut 500
        print(e)
        return make_response({"message": "Erreur lors de la création du rôle"}, 500)

# Route pour récupérer tous les rôles
@app.route("/roles", methods=["GET"])
def get_all_roles():
    try:
        # Récupération de tous les rôles de la base de données
        roles = Role.query.all()
        # Sérialisation des données des rôles
        serialized_roles = [role.serialize() for role in roles]
        # Retourner les données sérialisées avec le code de statut 200
        return jsonify({"data": serialized_roles}), 200
    except Exception as e:
        # En cas d'erreur, retourner un message d'erreur avec le code de statut 500
        print(e)
        return make_response({"message": f"Erreur: {str(e)}"}, 500)

# Route pour supprimer un rôle
@app.route("/roles/<int:role_id>", methods=["DELETE"])
def delete_role(role_id):
    try:
        # Récupération du rôle à supprimer en fonction de son ID
        role = Role.query.get(role_id)
        # Vérification si le rôle existe
        if not role:
            return make_response({"message": f"Le rôle avec l'ID {role_id} n'a pas été trouvé"}, 404)
        # Suppression du rôle de la base de données
        db.session.delete(role)
        db.session.commit()
        # Retourner un message de succès avec le code de statut 200
        return make_response({"message": "Rôle supprimé avec succès"}, 200)
    except Exception as e:
        # En cas d'erreur, retourner un message d'erreur avec le code de statut 500
        print(e)
        db.session.rollback()
        return make_response({"message": f"Impossible de supprimer le rôle: {str(e)}"}, 500)

# Route pour mettre à jour un rôle
@app.route("/roles/<int:role_id>", methods=["PUT"])
def update_role(role_id):
    try:
        # Récupération du rôle à mettre à jour en fonction de son ID
        role = Role.query.get(role_id)
        # Vérification si le rôle existe
        if not role:
            return make_response({"message": f"Le rôle avec l'ID {role_id} n'a pas été trouvé"}, 404)

        # Extraction des données du corps de la requête JSON
        data = request.json
        name = data.get("name")
        description = data.get("description")

        # Mise à jour des attributs du rôle
        if name:
            role.name = name
        if description:
            role.description = description

        # Enregistrement des modifications dans la base de données
        db.session.commit()

        # Retourner un message de succès avec les données mises à jour du rôle
        return make_response({"message": "Rôle mis à jour avec succès", "role": role.serialize()}, 200)
    except Exception as e:
        # En cas d'erreur, retourner un message d'erreur avec le code de statut 500
        print(e)
        db.session.rollback()
        return make_response({"message": "Impossible de mettre à jour le rôle"}, 500)



@app.route("/refresh_token", methods=["POST"])
def refresh_token():
    try:
        refresh_token = request.json.get("refresh_token")
        if not refresh_token:
            return jsonify({"message": "Refresh token is missing"}), 401
        try:
            current_user = jwt.decode(refresh_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            new_access_token = create_access_token(identity=current_user)
            return jsonify({"access_token": new_access_token}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Refresh token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid refresh token"}), 401
    except Exception as e:
        print(e)
        return jsonify({"message": "Unable to refresh token"}), 5

@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token 
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response

















# -------------------------------------------creer visite d'evaluation-----------------------------------------



@app.route('/user_info', methods=['GET'])
def get_user_info():
    email = request.args.get('email')
    user = Users.query.filter_by(email=email).first()
    if user:
        return jsonify({'firstName': user.firstName, 'lastName': user.lastName}), 200
    else:
        return jsonify({'error': 'Utilisateur non trouvé'}), 404



# Routes Flask
@app.route("/users", methods=["GET"])
def get_all_users():
    try:
        role_name = request.args.get('role')
        if role_name:
            users = Users.query.join(Role).filter(Role.name == role_name).all()
        else:
            users = Users.query.all()
         
        serialized_users = [user.serialize() for user in users]
        return jsonify(serialized_users), 200
    except Exception as e:
        print(e)
        return make_response({"message": f"Erreur: {str(e)}"}, 500)

    

# @app.route('/programme_visite', methods=['POST'])
# def create_programme_visite():
#     data = request.get_json()
#     new_programme = ProgrammeVisite(
#         periode_debut=data['periode_debut'],
#         periode_fin=data['periode_fin'],
#         criteres_evaluation=data['criteres_evaluation'],
#         lieu=data['lieu'],
#         description=data['description'],
#         contacts_urgence=data['contacts_urgence'],
#         conseiller_email=data['conseiller_email'],
#         admin_email=data['admin_email']  # Ajout de l'email de l'administration publique
#     )
#     db.session.add(new_programme)
#     db.session.commit()

#     return jsonify({"message": "Programme de visite créé avec succès "}), 201






# ------------------------------------------------------------------------------

from sqlalchemy import or_


@app.route('/programme_visite', methods=['POST'])
def create_programme_visite():
    data = request.get_json()
    conseiller_emails = data.get('conseiller_email')  # Liste des e-mails des conseillers
    users = Users.query.filter(or_(*[Users.email == email for email in conseiller_emails])).all()
    
    if users:
        for user in users:
            new_programme = ProgrammeVisite(
                periode_debut=data['periode_debut'],
                periode_fin=data['periode_fin'],
                criteres_evaluation=data['criteres_evaluation'],
                lieu=data['lieu'],
                description=data['description'],
                contacts_urgence=data['contacts_urgence'],
                user_id=user.id,
                conseiller_email=user.email,
                admin_email=data['admin_email']
            )
            db.session.add(new_programme)
        
        db.session.commit()
        return jsonify({"message": "Programme de visite créé avec succès "}), 201
    else:
        return jsonify({"message": "Aucun utilisateur trouvé"}), 404





# Configuration de Flask-Mail
app.config['SECRET_KEY'] = "tsfyguaistyatuis589566875623568956"
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "nourgarali12345@gmail.com"
app.config['MAIL_PASSWORD'] = "tmok wtxn cbia xobx"

mail = Mail(app)

from flask_mail import Message

@app.route('/send_email', methods=['POST'])
def send_email():
    try:
        data = request.json
        conseillers = data['conseillers']
        emailData = data['emailData']
        subject = emailData['subject']
        content = emailData['content']

        # Envoi de l'e-mail à chaque conseiller
        for conseiller in conseillers:
            msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[conseiller])
            msg.body = content
            mail.send(msg)

        return jsonify({'message': 'E-mails envoyés avec succès'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
    
    
    

@app.route('/ListeVisiteEvaluation', methods=['GET'])
def get_programmes_visite():
    try:
        conseiller_nom = request.args.get('nom')
        conseiller_prenom = request.args.get('prenom')

        if conseiller_nom and conseiller_prenom:
            # Recherche de l'utilisateur par nom et prénom (conseiller)
            user = Users.query.filter_by(firstName=conseiller_nom, lastName=conseiller_prenom).first()
            if user:
                # Récupération des programmes de visite associés à l'utilisateur
                programmes_visite = ProgrammeVisite.query.filter_by(user_id=user.id).all()
                # Sérialisation des programmes en JSON
                programmes_visite_json = [programme.serialize() for programme in programmes_visite]
                return jsonify(programmes_visite_json), 200
            else:
                return jsonify([]), 404
        else:
            # Si aucun conseiller n'est spécifié, renvoyer tous les programmes de visite
            programmes_visite = ProgrammeVisite.query.all()
            programmes_visite_json = [programme.serialize() for programme in programmes_visite]
            return jsonify(programmes_visite_json), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
    
    
from flask import jsonify, request
import requests  # Ajoutez cette ligne pour importer le module requests


@app.route('/conseillers')
def get_conseillers():
    conseillers = Users.query.join(Role).filter(Role.name == 'conseiller').all()
    return jsonify([conseiller.serialize() for conseiller in conseillers])



    # ----------------------------------------------fonction correct ----------------------------------
    


# Définir une route pour lister les programmes de visite d'un conseiller
@app.route('/conseillers/<string:nom>/<string:prenom>/programmes_visite', methods=['GET'])
def lister_programmes_visite_conseiller(nom, prenom):
    # Recherche de l'utilisateur par nom et prénom
    user = Users.query.filter_by(firstName=nom, lastName=prenom).first()
    if user:
        # Récupération des programmes de visite associés à l'utilisateur
        programmes = ProgrammeVisite.query.filter_by(user_id=user.id).all()
        # Sérialisation des programmes en JSON
        programmes_json = [programme.serialize() for programme in programmes]
        return jsonify(programmes_json)
    else:
        return jsonify([])  # Retourner une liste vide si l'utilisateur n'est pas trouvé



from flask import send_file
from io import BytesIO
from reportlab.pdfgen import canvas

from reportlab.lib.pagesizes import letter

    
# @app.route('/evaluation/<int:programme_id>', methods=['POST'])
# def submit_evaluation(programme_id):
#     data = request.json

#     # Extrait les données de l'évaluation depuis le JSON
#     observations = data.get('observations')
#     evaluations = data.get('evaluations')
#     recommendations = data.get('recommendations')

#     # Enregistre l'évaluation dans la base de données
#     try:
#         new_evaluation = Resultat(
#             programme_id=programme_id,
#             observations=observations,
#             evaluations=evaluations,
#             recommendations=recommendations
#         )
#         db.session.add(new_evaluation)
#         db.session.commit()

#         # Initialise pdf_io
#         pdf_io = BytesIO()

#         # Crée le PDF en utilisant pdf_io comme fichier en mémoire
#         p = canvas.Canvas(pdf_io)
#         p.drawString(100, 750, f"Observations: {observations}")
#         p.drawString(100, 735, f"Évaluations: {evaluations}")
#         p.drawString(100, 720, f"Recommandations: {recommendations}")
#         p.showPage()
#         p.save()

#         # Retourne le PDF comme réponse
#         pdf_io.seek(0)
#         response = make_response(pdf_io.getvalue())
#         response.headers['Content-Type'] = 'application/pdf'
#         response.headers['Content-Disposition'] = 'attachment; filename=rapport_evaluation.pdf'
#         return response
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'error': str(e)}), 500

    
    
    
    
UPLOAD_FOLDER = 'static/pdfRapport'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/evaluation/<int:programme_id>', methods=['POST'])
def submit_evaluation(programme_id):
    data = request.json

    # Extrait les données de l'évaluation depuis le JSON
    observations = data.get('observations')
    evaluations = data.get('evaluations')
    recommendations = data.get('recommendations')

    # Enregistre l'évaluation dans la base de données
    try:
        new_evaluation = Resultat(
            programme_id=programme_id,
            observations=observations,
            evaluations=evaluations,
            recommendations=recommendations
        )
        db.session.add(new_evaluation)
        db.session.commit()

        # Initialise pdf_io
        pdf_io = BytesIO()

        # Crée le PDF en utilisant pdf_io comme fichier en mémoire
        p = canvas.Canvas(pdf_io)
        p.drawString(100, 750, f"Observations: {observations}")
        p.drawString(100, 735, f"Évaluations: {evaluations}")
        p.drawString(100, 720, f"Recommandations: {recommendations}")
        p.showPage()
        p.save()

        # Sauvegarde le PDF sur le serveur
        pdf_filename = f"evaluation_{programme_id}.pdf"
        pdf_io.seek(0)
        with open(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename), 'wb') as f:
            f.write(pdf_io.read())

        # Retourne le PDF comme réponse
        pdf_io.seek(0)
        response = make_response(pdf_io.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=rapport_evaluation.pdf'
        return response
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
    
    
    
from flask import send_from_directory

@app.route('/programmes_visite/<int:programme_id>/rapport', methods=['GET'])
def get_programme_rapport(programme_id):
    try:
        # Rechercher le programme de visite dans la base de données par son ID
        programme = ProgrammeVisite.query.get(programme_id)
        
        # Vérifier si le programme existe
        if not programme:
            return jsonify({'error': 'Programme de visite non trouvé'}), 404
        
        # Vérifier si le fichier PDF existe sur le serveur
        pdf_filename = f"evaluation_{programme_id}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
        if not os.path.exists(pdf_path):
            return jsonify({'error': 'Rapport PDF introuvable'}), 404
        
        # Retourner le PDF en tant que fichier
        return send_from_directory(app.config['UPLOAD_FOLDER'], pdf_filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
    
    
    


import requests
import json

# Chemin local vers le fichier PDF que vous souhaitez partager
pdf_file_path = "static/pdfRapport/evaluation_1.pdf"

# Ouvrez le fichier PDF et lisez son contenu en tant que fichier binaire
with open(pdf_file_path, "rb") as file:
    pdf_content = file.read()

# Créez les données de la requête pour télécharger le fichier PDF en tant que pièce jointe
files = {
    "file": pdf_content
}

# Créez les données pour la publication sur Facebook
data = {
    "message": "Voici un fichier PDF intéressant",
    "published": "true",
}

# Ajoutez les en-têtes nécessaires (y compris l'autorisation)
headers = {
    "Authorization": "Bearer EAANo3OC0ZC0oBOwScOgUrIBYCfrhoHm5ug5wIxZAzGd9eFmvZBpVZA5sZAKoASR2yBwNcXWOB7cgEH9bfLkBJpw8ZCg6iTMjRo699r9P1rMHyVvdRo197MbGMjCUKEESwzkyedbX25qrwkRMNbYEN0pZBHMTYCV8pUpPXZB4g4FGw9WF9P2kk73wTJXshlDJqfj76clqIw8TL0Rd1UI5XLnrmdibzBUEYmMZD"
}

# Envoyez la requête pour télécharger le fichier PDF
response = requests.post("https://graph.facebook.com/v19.0/261223573746767/photos", headers=headers, data=data, files=files)

# Affichez la réponse
print(response.json())



if __name__ == '__main__':
    app.run(debug=True, port=5000)

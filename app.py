from functools import wraps
from sqlalchemy.sql import func
from . import app, db
from .models import Users, Instance, Role,ProgrammeVisite,db,Reunion,ArchivedUser,Resultat,UserReunion
from sqlalchemy import event
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
from datetime import datetime, timezone, timedelta
from werkzeug.utils import secure_filename
import os
from flask_mail import Mail, Message
from flask_jwt_extended import jwt_required, create_access_token, JWTManager, get_jwt_identity, get_jwt, create_refresh_token
import json
from flask import Flask, jsonify, request, make_response,redirect, url_for,session
from flask_cors import CORS
from flask import Flask, jsonify, request, make_response, flash,send_file,abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
import jwt
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from . import models
from . import app
from io import BytesIO
from itsdangerous import URLSafeTimedSerializer
from flask import send_from_directory



#app = Flask(__name__)
#CORS(app)


# Définition du dossier de téléchargement des fichiers
UPLOAD_IMAGE = 'static/uploads'
app.config['UPLOAD_IMAGE'] = UPLOAD_IMAGE


jwt = JWTManager(app)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

# Génération d'une clé secrète aléatoire
secret_key = os.urandom(24).hex()
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']  # Configurez l'emplacement du jeton JWT
app.config['JWT_SECRET_KEY'] = 'ons'  # Configurez la clé secrète JWT
# Configuration de l'application Flask avec la clé secrète
app.config['SECRET_KEY'] = secret_key
# Configuration de Flask-Mail avec vos coordonnées
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "benothmenons09@gmail.com"
app.config['MAIL_PASSWORD'] = "tvmg oqna uzjz etsf"
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'  # Adresse e-mail par défaut
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:postgres@localhost:5432/postgres"

# Initialise la base de données
#db.init_app(app)

# Initialisation de Flask-Mail
mail = Mail(app)

# Assurez-vous que le répertoire de téléchargement existe
if not os.path.exists(UPLOAD_IMAGE):
    os.makedirs(UPLOAD_IMAGE)

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
from flask import jsonify

@app.route('/signup/<int:newUserId>', methods=['POST'])
def signup(newUserId):  # Utilisez newUserId comme paramètre de route
    roles = Role.query.all()
    roles_data = [{"id": role.id, "name": role.name} for role in roles]

    if 'avatar' not in request.files:
        return jsonify({"message": "Aucun fichier d'avatar n'a été envoyé"}), 400

    avatar = request.files['avatar']

    if avatar.filename == '':
        return jsonify({"message": "Aucun fichier sélectionné"}), 400

    if avatar and allowed_file(avatar.filename):
        filename = secure_filename(avatar.filename)
        avatar.save(os.path.join(app.config['UPLOAD_IMAGE'], filename))

        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        email = request.form.get('email')
        password = request.form.get('password')
        phone_number = request.form.get('phoneNumber')
        address = request.form.get('address')

        hashed_password = generate_password_hash(password)

        # Rechercher l'utilisateur existant avec l'ID spécifié
        existing_user = Users.query.filter_by(id=newUserId).first()

        if existing_user:
            # Mettre à jour les champs de l'utilisateur existant avec les nouvelles données
            existing_user.firstName = first_name
            existing_user.lastName = last_name
            existing_user.email = email
            existing_user.password = hashed_password
            existing_user.phoneNumber = phone_number
            existing_user.address = address
            existing_user.profile_image = filename
            existing_user.is_active = True  # Modifier is_active en True


            db.session.commit()

            return jsonify({"message": "Utilisateur mis à jour avec succès"}), 200
        else:
            return jsonify({"message": "Utilisateur non trouvé"}), 404
    else:
        return jsonify({"message": "Extension de fichier non autorisée"}), 400


def send_email_to_president(president_email, instance_name, ville, new_user_id):
    try:
        # Lien d'inscription avec l'ID de l'utilisateur
        signup_link = f"http://localhost:3000/signup/{new_user_id}"

        # Créer le message d'e-mail avec le lien d'inscription
        message_body = (f"Bienvenue Monsieur/Madame le président,\n\n"
                        f"Une nouvelle instance a été créée pour votre gestion. Les détails sont les suivants :\n\n"
                        f"Nom de l'instance : {instance_name}\n"
                        f"Ville : {ville}\n\n"
                        f"Pour vous inscrire, veuillez cliquer sur le lien suivant :\n"
                        f"{signup_link}\n\n"
                        f"Merci de prendre les mesures nécessaires.\n\n"
                        f"Cordialement,\nVotre application")

        message = Message(subject="Nouvelle instance créée",
                          recipients=[president_email],
                          body=message_body)

        # Envoyer l'e-mail
        mail.send(message)  # Assurez-vous d'avoir configuré Flask-Mail correctement dans votre application

        # Enregistrer les détails de l'email envoyé dans la base de données
        sent_email = SentEmail(
            president_email=president_email,
            subject="Nouvelle instance créée",
            body=message_body,
            sent_at=datetime.now()
        )
        db.session.add(sent_email)
        db.session.commit()
    except Exception as e:
        print("Error sending email:", e)

@app.route("/resendEmailToPresident/<int:instance_id>", methods=["POST"])
def resend_email_to_president(instance_id):
    try:
        # Récupérer les détails de l'instance à partir de la base de données
        instance = Instance.query.get(instance_id)
        if not instance:
            return make_response({"message": "Instance not found"}, 404)

        # Récupérer l'utilisateur associé à cette instance
        user = Users.query.filter_by(instance_id=instance_id).first()
        if not user:
            return make_response({"message": "User not found"}, 404)

        # Extraire l'ID de l'utilisateur
        new_user_id = user.id

        # Récupérer l'e-mail du président associé à cette instance
        president_email = instance.president_email

        # Appeler la fonction pour renvoyer l'e-mail au président
        send_email_to_president(president_email, instance.instance_name, instance.ville, new_user_id)

        return make_response({"message": "Email resent successfully"}, 200)
    except Exception as e:
        print("Error resending email:", e)
        return make_response({"message": "Internal server error"}, 500)



@app.route("/login", methods=["POST"])
def login():
    auth = request.json
    email = auth.get("email")  # Récupérer l'email de la requête
    password = auth.get("password")  # Récupérer le mot de passe de la requête


    # Enregistrer les données de connexion dans la console
    print(f"Email: {email}, Mot de passe: {password}")

    # Trouver l'utilisateur dans la base de données par son email
    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Utilisateur non trouvé"}), 404

    # Vérifier le mot de passe seulement si l'utilisateur existe
    if not check_password_hash(user.password, password):
        return jsonify({'message': 'Veuillez vérifier vos informations de connexion'}), 401
    
    # Vérifier si le compte utilisateur est archivé
    if user.is_archived:
        return jsonify({"message": "Votre compte est archivé. Veuillez contacter l'administrateur."}), 401

    print(f"ID de l'utilisateur connecté : {user.id}")


    # Obtenir l'ID de l'instance associée à l'utilisateur
    instance_id = user.instance_id

    # Récupérer l'objet Instance correspondant à l'ID de l'instance
    instance = Instance.query.get(instance_id)

    # Extraire l'ID de l'instance
    instance_id = instance.id if instance else None

    # Créer la charge utile du jeton avec l'ID de l'instance inclus
    token_payload = {
        'id': user.id,
        'role': user.role.name if user.role else None,
        'email': user.email,
        'firstName': user.firstName,
        'lastName': user.lastName,
        "phoneNumber": user.phoneNumber,
        "address": user.address,
        "profile_image": user.profile_image,
        "instance_id": instance_id  # Inclure l'ID de l'instance dans la charge utile du jeton
    }

    # Générer le jeton JWT
    token = create_access_token(identity=token_payload)
    
    # Retourner les informations du profil utilisateur avec le jeton d'accès
    return jsonify({"token": token, "profile": token_payload}), 200





@app.route('/user/<int:user_id>/conseillers', methods=['GET'])
def get_nb_conseillers(user_id):
    user = Users.query.get(user_id)
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'nb_conseillers': user.instance.nombre_conseille})

@app.route('/user/<int:user_id>/inst', methods=['GET'])
def get_inst(user_id):
    user = Users.query.get(user_id)

    if user is None:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'nom_instance': user.instance.id})



def send_invitation_email(email, instance_name, ville, new_user_id):
    try:
        # Lien d'inscription
        signup_link = "http://localhost:3000/signup"

        # Créer le message d'e-mail avec le lien d'inscription
        message_body = (f"Bienvenue,\n\n"
                        f"Vous avez été invité à rejoindre l'instance '{instance_name}' située à {ville}.\n\n"
                        f"Pour vous inscrire, veuillez cliquer sur le lien suivant :\n"
                        f"{signup_link}\n\n"
                        f"Merci de votre participation.\n\n"
                        f"Cordialement,\nVotre application")

        # Envoyer l'e-mail
        message = Message(subject="Invitation à rejoindre l'instance",
                          recipients=[email],
                          body=message_body)

        mail.send(message)  # Assurez-vous d'avoir configuré Flask-Mail correctement dans votre application
    except Exception as e:
        print("Error sending email:", e)

from flask import request, jsonify
import requests

@app.route('/addConseille', methods=['POST'])
def add_conseille():
    data = request.json
    user_id = data.get('user_id')
    counselors = data.get('counselors')

    print(f"ID de l'utilisateur qui fait la requête : {user_id}")


    # Récupérer l'ID de l'instance de l'utilisateur
    instance_id_response = requests.get(f'http://localhost:5000/user/{user_id}/inst')
    if instance_id_response.status_code == 200:
        instance_info = instance_id_response.json()
        instance_id = instance_info.get('nom_instance')  # Récupérer l'ID de l'instance
        instance_name = instance_info.get('nom_instance')  # Vous avez besoin du nom de l'instance?
        user_email = instance_info.get('email')  # Vous avez besoin de l'email de l'instance?
    else:
        return jsonify({'error': 'Failed to retrieve instance information'}), 500


    # Ajouter les conseillers et envoyer les invitations
    for counselor in counselors:
        email = counselor.get('email')

        # Créer un nouvel utilisateur avec l'ID de l'instance
        new_user = Users(instance_id=instance_id)
        db.session.add(new_user)
        db.session.flush()  # Flusher pour obtenir new_user.id avant le commit

        # Envoyer l'invitation à l'utilisateur nouvellement ajouté
        send_invitation_emailConseille(email, instance_name, new_user.id)

    db.session.commit()

    return jsonify({'message': 'Conseillers ajoutés avec succès'}), 200



def send_invitation_emailConseille(email, instance_name, new_user_id):
    try:
        # Lien d'inscription avec instance_name et new_user_id
        signup_link = f"http://localhost:3000/register/{new_user_id}"

        # Créer le message d'e-mail avec le lien d'inscription
        message_body = (f"Bienvenue,\n\n"
                        f"Vous avez été invité à rejoindre l'instance '{instance_name}'.\n\n"
                        f"Pour vous inscrire, veuillez cliquer sur le lien suivant :\n"
                        f"{signup_link}\n\n"
                        f"Merci de votre participation.\n\n"
                        f"Cordialement,\nVotre application")

        # Envoyer l'e-mail
        message = Message(subject="Invitation à rejoindre l'instance",
                          recipients=[email],
                          body=message_body)

        mail.send(message)  # Assurez-vous d'avoir configuré Flask-Mail correctement dans votre application
    except Exception as e:
        print("Error sending email:", e)


@app.route('/register/<int:new_user_id>', methods=['POST'])
def register(new_user_id):
    try:
        # Extraire les données du formulaire
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        email = request.form.get('email')
        address = request.form.get('address')
        phone_number = request.form.get('phoneNumber')

        # Gérer le fichier d'avatar
        if 'avatar' not in request.files:
            return jsonify({"message": "Aucun fichier d'avatar n'a été envoyé"}), 400

        avatar = request.files['avatar']

        # Vérifier si aucun fichier n'a été sélectionné
        if avatar.filename == '':
            return jsonify({"message": "Aucun fichier sélectionné"}), 400

        # Sécuriser le nom du fichier et enregistrer l'avatar
        avatar_filename = secure_filename(avatar.filename)
        avatar_path = os.path.join(app.config['UPLOAD_IMAGE'], avatar_filename)
        avatar.save(avatar_path)

        # Extraire l'ID du rôle 'conseiller'
        role_conseiller = Role.query.filter_by(name='conseiller').first()
        if not role_conseiller:
            return jsonify({'error': 'Role conseiller not found'}), 404
        role_id = role_conseiller.id

        # Rechercher l'utilisateur dans la base de données par son ID
        existing_user = Users.query.get(new_user_id)
        if not existing_user:
            return jsonify({'error': 'User not found'}), 404

        # Mettre à jour les détails de l'utilisateur
        existing_user.firstName = first_name
        existing_user.lastName = last_name
        existing_user.email = email
        existing_user.profile_image = avatar_filename
        existing_user.address = address
        existing_user.phoneNumber = phone_number
        existing_user.role_id = role_id
        existing_user.is_active = True  # Mettre à jour is_active à 'true'

        # Enregistrer les modifications dans la base de données
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
from flask import request, jsonify

@app.route('/add_password/<int:new_user_id>', methods=['POST'])
def add_password(new_user_id):
    try:
        # Extraire le mot de passe et sa confirmation du formulaire
        password = request.json.get('password')
        confirm_password = request.json.get('confirmPassword')  # Assurez-vous que le nom du champ est correct

        # Vérifier si les mots de passe correspondent
        if password != confirm_password:
            return jsonify({"error": "Les mots de passe ne correspondent pas"}), 400

        # Hasher le mot de passe
        hashed_password = generate_password_hash(password)

        # Rechercher l'utilisateur dans la base de données par son ID
        existing_user = Users.query.get(new_user_id)
        if not existing_user:
            return jsonify({'error': 'User not found'}), 404

        # Mettre à jour le mot de passe de l'utilisateur
        existing_user.password = hashed_password

        # Enregistrer les modifications dans la base de données
        db.session.commit()

        return jsonify({'message': 'Mot de passe ajouté avec succès'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/images/<filename>')
def uploaded_file(filename):
    return send_from_directory('C:/Users/Ons/Pictures', filename)

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
    if current_user.role.name != 'président':
        return make_response({'message': 'Permission denied'}, 403)
    # Logique pour le tableau de bord du président

@app.route("/superAdmin_dashboard")
@token_required
def superAdmin_dashboard(current_user):
    if current_user.role.name != 'super admin':
        return make_response({'message': 'Permission denied'}, 403)
    
@app.route("/admin_dashboard")
@token_required
def admin_dashboard(current_user):
    if current_user.role.name != 'adminPublique':
        return make_response({'message': 'Permission denied'}, 403)



@app.route("/conseille")
@token_required
def conseille_dashboard(current_user):
    if current_user.role.name != 'conseiller':
        return make_response({'message': 'Permission denied'}, 403)


@app.route('/user_image/<int:user_id>')
def user_image(user_id):
    user = Users.query.get(user_id)
    if user and user.profile_image:
        return send_file(
            BytesIO(user.profile_image),
            attachment_filename='profile_image.png',
            mimetype='image/png'
        )
    return 'Image non trouvée', 404

@app.route("/Allusers", methods=["GET"])
def users():
    try:
        role_name = request.args.get('role')
        if role_name:
            users = Users.query.join(Role).filter(Role.name == role_name).filter_by(is_archived=False, is_active=True).all()
            if role_name == 'président':
                serialized_users = [{"email": user.email} for user in users]
            else:
                serialized_users = [user.serialize() for user in users]
            return jsonify({"data": serialized_users}), 200
        else:
            users = Users.query.filter_by(is_archived=False, is_active=True).all()  # Exclure les utilisateurs archivés
            serialized_users = [user.serialize() for user in users]
            return jsonify({"data": serialized_users}), 200
    except Exception as e:
        print(e)
        return make_response({"message": f"Erreur: {str(e)}"}, 500)



        
@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            return make_response({"message": f"User with id {user_id} not found"}, 404)

        # Récupérer les données de la requête
        data = request.json

        # Mettre à jour les champs de l'utilisateur
        if 'firstName' in data:
            user.firstName = data['firstName']
        if 'lastName' in data:
            user.lastName = data['lastName']
        if 'email' in data:
            user.email = data['email']
        if 'phoneNumber' in data:
            user.phoneNumber = data['phoneNumber'] 
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_IMAGE'], filename))

                # Mettre à jour le chemin de l'image de profil dans la base de données
                user.profile_image = filename

        db.session.commit()

        return jsonify({"message": "User updated successfully", "user": user.serialize()}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to update user"}, 500)

@app.route("/users/<int:user_id>/disable", methods=["PUT"])
def disable_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            return make_response({"message": f"User with id {user_id} not found"}, 404)

        # Désactiver l'utilisateur
        user.active = False
        db.session.commit()

        return jsonify({"message": "User disabled successfully"}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to disable user"}, 500)

@app.route("/users/<int:user_id>/enable", methods=["PUT"])
def enable_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            return make_response({"message": f"User with id {user_id} not found"}, 404)

        # Réactiver l'utilisateur
        user.active = True
        db.session.commit()

        return jsonify({"message": "User enabled successfully"}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to enable user"}, 500)

@app.route('/users/<int:user_id>/archive', methods=['POST'])
def archive_user(user_id):
    user = Users.query.get_or_404(user_id)
    user.is_archived = True
    db.session.commit()
    return jsonify({'message': 'Utilisateur archivé avec succès'}), 200

@app.route('/users/<int:user_id>/activate', methods=['POST'])
def activate_user(user_id):
    # Recherche de l'utilisateur par son ID dans la base de données
    user = Users.query.filter_by(id=user_id).first()
    if user:
        # Mettre à jour la propriété is_archived à False
        user.is_archived = False
        # Sauvegarder les modifications dans la base de données
        db.session.commit()
        return jsonify({'message': 'Utilisateur activé avec succès'}), 200
    else:
        return jsonify({'error': 'Utilisateur non trouvé'}), 404


from sqlalchemy import text

@app.route('/api/archived-user', methods=['GET'])
def get_archived_users():
    try:
        # Query the Users model to retrieve archived users
        archived_users = Users.query.filter_by(is_archived=True, is_active=True).all()

        # Serialize the archived user objects to JSON format
        serialized_users = []
        for user in archived_users:
            serialized_user = user.serialize()
            # Ajouter l'avatar à la sérialisation de l'utilisateur
            serialized_user['profile_image'] = user.profile_image
            serialized_users.append(serialized_user)

        # Return the serialized users as a JSON response
        return jsonify(serialized_users), 200
    except Exception as e:
        print(e)
        return make_response({"message": f"Erreur: {str(e)}"}, 500)



@app.route('/users/not-registered', methods=['GET'])
def get_users_not_registered():
    # Récupérer l'email de l'instance à partir des paramètres de requête
    instance_email = request.args.get('instance_email')

    if instance_email:
        # Recherche de l'instance par son email
        instance = Instance.query.filter_by(president_email=instance_email).first()

        if instance:
            # Récupération de tous les utilisateurs ayant l'email de l'instance et non inscrits
            users_not_registered = Users.query.filter_by(email=instance_email, instance_id=instance.id, is_active=False).all()

            # Sérialisation des données des utilisateurs
            serialized_users = [user.serialize() for user in users_not_registered]

            # Maintenant, nous récupérons également les emails des présidents des instances actives non archivées
            presidents = db.session.query(Users.email).join(Instance, Users.instance_id == Instance.id)\
                             .filter(Instance.active == True, Instance.is_archived == False)\
                             .all()
            president_emails = [president[0] for president in presidents]

            return jsonify(serialized_users, president_emails)
        else:
            return jsonify({'error': 'Instance not found'})
    else:
        return jsonify({'error': 'Instance email not provided'})




@app.route('/update_profile/<int:user_id>', methods=['PUT'])
def update_profile(user_id):
    user = Users.query.get(user_id)
    if not user:
        abort(404, description=f"User with id {user_id} not found")

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
            filepath = os.path.join(app.config['UPLOAD_IMAGE'], filename)
            image.save(filepath)
            user.profile_image = filename
            print(f"Image '{filename}' saved successfully in the database.")
        else:
            return jsonify({"message": "Allowed image types are png, jpg, jpeg, gif"}), 400

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        abort(500, description=str(e))

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
    instance_name = data.get("instance_name")
    nombre_conseille = data.get("nombre_conseille")
    ville = data.get("ville")  
    active = data.get("active")
    created_at = data.get("created_at")
    gouvernement = data.get("gouvernement")

    if president_email and instance_name and ville:  
        instance = Instance.query.filter_by(president_email=president_email).first()
        if instance:
            return make_response({"message": "Instance already exists"}, 200)

        new_instance = Instance(
            president_email=president_email,
            instance_name=instance_name,
            nombre_conseille=nombre_conseille,
            ville=ville,
            active=active if active is not None else True,
            created_at=created_at,
            gouvernement=gouvernement
        )
        db.session.add(new_instance)
        db.session.commit()

        instance_id = new_instance.id

        # Créer un nouvel enregistrement dans la classe Users avec seulement l'ID de l'instance
        new_user = Users(
            instance_id=instance_id
        )
        db.session.add(new_user)
        db.session.commit()

        send_email_to_president(president_email, instance_name, ville, new_user.id)


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
    instance.nombre_conseille = data.get('nombre_conseille', instance.nombre_conseille)
    instance.ville = data.get('ville', instance.ville)
    instance.active = data.get('active', instance.active)
    instance.gouvernement = data.get('gouvernement',instance.gouvernement)
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

from flask import jsonify

@app.route('/inactive_presidents', methods=['GET'])
def inactive_presidents():
    try:
        # Récupérer les instances ayant un utilisateur avec is_active=False
        instances_with_inactive_users = Instance.query.join(Users).filter(Users.is_active == False).with_entities(Instance.president_email).all()
        
        # Convertir la liste de tuples en liste de chaînes
        inactive_presidents_emails = [instance[0] for instance in instances_with_inactive_users]
        
        return jsonify(inactive_presidents_emails), 200
    except Exception as e:
        print(str(e))
        return jsonify({"error": "An error occurred while fetching inactive presidents"}), 500

# Définir une fonction pour rechercher une instance par n'importe quel champ
def search_instance(query):
    instances = Instance.query.filter(or_(
        Instance.instance_name.ilike(f'%{query}%'),
        Instance.president_email.ilike(f'%{query}%'),
        Instance.gouvernement.ilike(f'%{query}%'),
        Instance.ville.ilike(f'%{query}%')
    )).all()
    return instances


# Route pour la recherche d'instances par n'importe quel champ
@app.route('/instances/search', methods=['GET'])
def search_instances():
    query = request.args.get('q')  # Récupérer le paramètre de requête 'q'
    if query:
        instances = search_instance(query)
        if instances:
            serialized_instances = [instance.serialize() for instance in instances]
            return jsonify(serialized_instances), 200
        else:
            return jsonify({"message": "No instances found for the given query"}), 404
    else:
        return jsonify({"message": "Query parameter is required"}), 400

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


@app.route('/api/change-password', methods=['POST'])
def change_password():
    data = request.json
    user_id = data.get('userId')
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')

    user = Users.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Vérifiez si le mot de passe actuel fourni correspond au mot de passe actuel de l'utilisateur
    if not check_password_hash(user.password, current_password):
        return jsonify({'message': 'Incorrect current password'}), 400

    # Hash du nouveau mot de passe et mise à jour dans la base de données
    user.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({'message': 'Password updated successfully'}), 200


import random
import string

@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.json.get("email")
    # Vérifier si l'e-mail existe dans la base de données
    user = Users.query.filter_by(email=email).first()
    if user:
        # Générer un code de vérification aléatoire
        verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        # Enregistrer le code de vérification pour cet utilisateur
        user.verification_code = verification_code
        db.session.commit()
        # Envoyer le code de vérification à l'utilisateur (par e-mail, SMS, etc.)
        send_verification_email(email, verification_code)
        return jsonify({"message": "Un code de vérification a été envoyé à votre adresse e-mail."}), 200
    else:
        return jsonify({"error": "Adresse e-mail non trouvée"}), 404


def send_verification_email(email, verification_code):
    try:
        subject = 'Réinitialisation du mot de passe'
        message = f'Voici votre code de vérification pour réinitialiser votre mot de passe : {verification_code}'
        
        # Configuration du message
        msg = Message(subject, recipients=[email])
        msg.body = message

        # Envoi de l'e-mail
        mail.send(msg)
    except Exception as e:
        print("Erreur lors de l'envoi de l'e-mail de vérification :", str(e))

import hashlib

@app.route('/ResetPassword', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    verification_code = data.get('verification_code')
    new_password = data.get('new_password')

    # Vérifiez si l'utilisateur existe avec l'email donné et le code de vérification
    user = Users.query.filter_by(email=email, verification_code=verification_code).first()
    if user:
        # Mettez à jour le mot de passe de l'utilisateur
        user.password = generate_password_hash(new_password)  # Générer le hachage du nouveau mot de passe
        db.session.commit()
        return jsonify({'message': 'Mot de passe réinitialisé avec succès'}), 200
    else:
        return jsonify({'message': 'Adresse e-mail ou code de vérification incorrect'}), 400

@app.route('/getlistconseille', methods=['GET'])
@jwt_required()
def get_list_conseille():
    try:
        # Afficher un message indiquant que la route a été appelée
        print("Route /getlistconseille a été appelée")

        # Récupérer l'ID de l'utilisateur connecté depuis le JWT
        user_identity = get_jwt_identity()

        # Afficher l'ID de l'utilisateur connecté
        print(f"ID de l'utilisateur connecté : {user_identity['id']}")

        # Récupérer l'instance de l'utilisateur connecté
        instance_id_response = requests.get(f'http://localhost:5000/user/{user_identity["id"]}/inst')
        if instance_id_response.status_code == 200:
            instance_info = instance_id_response.json()
            instance_id = instance_info.get('nom_instance')  # Récupérer l'ID de l'instance

            # Afficher l'ID de l'instance
            print(f"ID de l'instance récupérée : {instance_id}")

            if not instance_id:
                print("Instance ID not found in the response")
                return jsonify({'error': 'Instance ID not found in the response'}), 500
        else:
            print("Failed to retrieve instance information")
            return jsonify({'error': 'Failed to retrieve instance information'}), 500

        # Récupérer tous les utilisateurs avec le rôle de conseiller (role_id = 3) et le même ID d'instance
        counselors = Users.query.filter_by(instance_id=instance_id, role_id=3).all()

        # Afficher le nombre de conseillers trouvés
        print(f"Nombre de conseillers trouvés : {len(counselors)}")

        # Sérialiser les conseillers
        serialized_counselors = [counselor.serialize() for counselor in counselors]

        # Afficher les conseillers sérialisés
        print(f"Conseillers sérialisés : {serialized_counselors}")

        return jsonify(serialized_counselors), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Une erreur s\'est produite lors de la récupération des conseillers'}), 500










# -------------------------------------------creer visite d'evaluation-----------------------------------------



# @app.route('/user_info', methods=['GET'])
# def get_user_info():
#     email = request.args.get('email')
#     user = Users.query.filter_by(email=email).first()
#     if user:
#         return jsonify({'firstName': user.firstName, 'lastName': user.lastName}), 200
#     else:
#         return jsonify({'error': 'Utilisateur non trouvé'}), 404



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
                admin_email=data['admin_email'],
                nomProgramme=data['nomProgramme'],
                nomAdminPublique=data['nomAdminPublique']
            )
            db.session.add(new_programme)
        
        db.session.commit()
        return jsonify({"message": "Programme de visite créé avec succès "}), 201
    else:
        return jsonify({"message": "Aucun utilisateur trouvé"}), 404



@app.route('/get_admin_name', methods=['GET'])
def get_admin_name():
    admin_email = request.args.get('admin_email')  # Récupérer l'email de l'administration publique depuis la requête
    admin_user = Users.query.filter_by(email=admin_email).first()
    if admin_user:
        admin_first_name = admin_user.firstName
        admin_last_name = admin_user.lastName
        return {"firstName": admin_first_name, "lastName": admin_last_name}
    else:
        return "Aucun utilisateur trouvé pour cet e-mail."





# # Configuration de Flask-Mail
# app.config['SECRET_KEY'] = "tsfyguaistyatuis589566875623568956"
# app.config['MAIL_SERVER'] = "smtp.googlemail.com"
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = "nourgarali12345@gmail.com"
# app.config['MAIL_PASSWORD'] = "tmok wtxn cbia xobx"

#mail = Mail(app)

#from flask_mail import Message


@app.route('/send_email', methods=['POST'])
def send_email():
    data = request.json
    emailData = data['emailData']
    admin_email = data.get('admin_email')  # Vérifier si l'e-mail de l'administration est fourni
    conseillers = data.get('conseillers')
    
    # Envoyer l'e-mail aux conseillers
    if conseillers:
        for conseiller_email in conseillers:
            msg = Message(emailData['subject'], recipients=[conseiller_email])
            msg.body = emailData['content']
            mail.send(msg)
    
    # Envoyer l'e-mail à l'administration
    if admin_email:
        msg_admin = Message(emailData['subject'], recipients=[admin_email])
        msg_admin.body = emailData['content']
        mail.send(msg_admin)
    
    return jsonify({'message': 'E-mails envoyés avec succès'}), 200

    
    
    

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

UPLOAD_FOLDER = 'static/pdfRapport'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
import requests
import fitz
import os

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from babel.dates import format_datetime
import datetime
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER





# -------------------------------créer evaluation-----------------------------------------


@app.route('/evaluation/<int:programme_id>', methods=['POST'])
def submit_evaluation(programme_id):
    data = request.json

    # Extrait les données de l'évaluation depuis le JSON
    observations = data.get('observations')
    evaluations = data.get('evaluations')
    recommendations = data.get('recommendations')

    try:
        # Récupérer les informations sur le programme de visite à partir de la base de données
        programme_visite = ProgrammeVisite.query.get(programme_id)
        lieu = programme_visite.lieu  # Supposons que le lieu soit un attribut de votre modèle ProgrammeVisite
        periode_debut = format_datetime(programme_visite.periode_debut, format='d MMMM yyyy', locale='fr_FR')
        description = programme_visite.description
        nom_programme = programme_visite.nomProgramme

        # Enregistre l'évaluation dans la base de données
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
        doc = SimpleDocTemplate(pdf_io, pagesize=letter)

        # Prépare le contenu du PDF
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,  # Augmentez la taille de la police ici
            alignment=TA_CENTER,
            spaceAfter=12,
        )
        bold_style = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontName='Helvetica-Bold'
        )
        Story = []  # Supprimez le Spacer ici

        # Ajoute le texte au PDF
        text = f"""
        <para align=center><b>Rapport d'Évaluation</b></para>

        <b>Programme de Visite:</b> {nom_programme}
        <b>Lieu :</b> {lieu}
        <b>date :</b> {periode_debut}
        <b>Évalué par:</b> [Nom de l'évaluateur]
        <b>Introduction</b>
        Le cadre de notre engagement continu envers l’amélioration de la gouvernance locale, une visite d’évaluation a été effectuée au {lieu} le {periode_debut}. Cette visite s’inscrit dans une série d’efforts visant à optimiser les services offerts aux citoyens et à renforcer la transparence des opérations des conseils locaux.
        <b>Objectifs de la Visite :</b>
        {description}
        <b>Observations et Évaluations</b>
        Les observations faites lors de la visite ont révélé que :
        {observations}
        <b>Recommandations</b>
        Sur la base des évaluations, nous recommandons les actions suivantes :
        {recommendations}
        Ce rapport, synthétisant nos observations, évaluations et recommandations, sera partagé avec la communauté via notre page Facebook pour garantir une transparence totale et encourager une participation citoyenne active dans le processus d’amélioration continue.
        <b>Conclusion</b>
        Cette visite a permis de mettre en lumière les forces et les faiblesses des services évalués. Les recommandations fournies visent à guider les efforts d’amélioration continue. Nous restons dédiés à l’excellence dans la prestation de services aux citoyens et à la promotion d’une gouvernance locale efficace et transparente.
        """
        for line in text.split('\n'):
            p = Paragraph(line, bold_style if any(keyword in line for keyword in ["Lieu", "Date", "Introduction", "Objectifs de la Visite", "Observations", "Évaluations", "Recommandations"]) else styles["Normal"])
            Story.append(p)
            Story.append(Spacer(1,0.2*inch))

        # Construit le PDF
        doc.build(Story)

        # Sauvegarde le PDF sur le serveur
        pdf_filename = f"evaluation_{programme_id}.pdf"
        pdf_io.seek(0)
        with open(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename), 'wb') as f:
            f.write(pdf_io.read())

        # Partage automatique sur Facebook
        share_on_facebook(pdf_filename)  # Assurez-vous d'implémenter cette fonction

        # Retourne le PDF comme réponse
        pdf_io.seek(0)
        response = make_response(pdf_io.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=rapport_evaluation.pdf'
        return response
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    


    
def share_on_facebook(pdf_filename):
    # Ouvrir le fichier PDF
    pdf_file_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
    doc = fitz.open(pdf_file_path)

    # Récupérer la première image de la première page du PDF
    page = doc.load_page(0)
    pixmap = page.get_pixmap()

    # Créer un fichier temporaire pour stocker l'image
    image_temp_path = "temp_image.jpg"
    pixmap.save(image_temp_path)

    # Ouvrir le fichier image et le lire en tant que fichier binaire
    with open(image_temp_path, "rb") as file:
        image_content = file.read()

    # Créer les données de la requête pour télécharger l'image en tant que pièce jointe
    files = {
        "file": ("temp_image.jpg", image_content, "image/jpeg")
    }

    # Créer les données pour la publication sur Facebook
    data = {
        "message": "Voici le rapport d'évaluation",
        "published": "true",
    }

    # Ajouter les en-têtes nécessaires (y compris l'autorisation)
    headers = {
        "Authorization": "Bearer EAANo3OC0ZC0oBO8g6XCs4OB7WSsxwA0nMZBKcNFRBswU9c9G34ZB5PqwpYDGZAQ5jSqTtiwFnu6cueBeUCYyBnQWCDeiPmToqovTLdFqx9zluRCYPmJy1tJ0iLqUjlnfRWNdGRPy2hdlCmT92oW8jMllHtKAB7grtii7bB9ykVhtMfXF22daxnSIZCbyfV9ImG8bju2Bq02tqujDZCceEXt49ikbA9cvgZD"
    }

    # Envoyer la requête pour télécharger l'image
    response = requests.post("https://graph.facebook.com/v19.0/261223573746767/photos", headers=headers, data=data, files=files)

    # Afficher la réponse
    print(response.json())





@app.route('/programmes_visite/<int:programme_id>/rapport', methods=['GET'])
def get_programme_rapport(programme_id):
    try:
        # Rechercher le programme de visite dans la base de données par son ID
        programme = ProgrammeVisite.query.get(programme_id)
        
        # Vérifier si le programme existe
        if not programme:
            return jsonify({'error': 'Programme de visite non trouvé'}), 404
        
        # Vérifier si le programme a un résultat associé
        if not programme.resultat:
            return jsonify({'error': 'Aucun rapport associé à ce programme de visite'}), 404
        
        # Vérifier si le fichier PDF existe sur le serveur
        pdf_filename = f"evaluation_{programme_id}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
        if not os.path.exists(pdf_path):
            return jsonify({'error': 'Rapport PDF introuvable'}), 404
        
        # Retourner le PDF en tant que fichier
        return send_from_directory(app.config['UPLOAD_FOLDER'], pdf_filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/programmes_visite/<int:programme_id>/statut', methods=['PUT'])
def update_programme_statut(programme_id):
    new_statut = request.json.get('statut')
    programme = ProgrammeVisite.query.get(programme_id)
    if programme:
        programme.statut = new_statut
        db.session.commit()
        return jsonify({'success': True, 'message': 'Statut mis à jour avec succès.'}), 200
    else:
        return jsonify({'success': False, 'message': 'Programme de visite non trouvé.'}), 404
    
    
    

@app.route('/archived_programmes_visite')
def get_archived_programmes_visite():
    # Récupérez les programmes de visites clôturés depuis la base de données
    archived_programmes_visite = ProgrammeVisite.query.filter_by(statut='Clôturé').all()
    # Serialisez les données au format JSON
    serialized_archived_programmes_visite = [programme.serialize() for programme in archived_programmes_visite]
    # Renvoyez les données JSON
    return jsonify(serialized_archived_programmes_visite)




# ----------------------------------------PV REUNION --------------------------------------------




@app.route('/reunions', methods=['POST'])
def ajouter_reunion():
    try:
        data = request.get_json()
        type_reunion = data.get('type_reunion')
        date = data.get('date')
        heure = data.get('heure')
        ordre_du_jour = data.get('ordre_du_jour')
        participants_emails = data.get('participants')

        if type_reunion == 'presentielle':
            lieu = data.get('lieu')
            nouvelle_reunion = Reunion(type_reunion=type_reunion, date=date, heure=heure, lieu=lieu, ordre_du_jour=ordre_du_jour)
        elif type_reunion == 'meet':
            lien_meet = data.get('lien_meet')
            nouvelle_reunion = Reunion(type_reunion=type_reunion, date=date, heure=heure, lien_meet=lien_meet, ordre_du_jour=ordre_du_jour)
        
        db.session.add(nouvelle_reunion)
        db.session.commit()

        # Ajouter les participants à la réunion
        for email in participants_emails:
            user = Users.query.filter_by(email=email).first()
            if user:
                user_reunion = UserReunion(user_id=user.id, reunion_id=nouvelle_reunion.id)
                db.session.add(user_reunion)
        
        db.session.commit()

        # Envoyer les invitations par email
        for email in participants_emails:
            msg = Message(subject="Invitation à la réunion",
                          recipients=[email],
                          body=f"Nous avons le plaisir de vous inviter à la réunion du conseil local  qui se tiendra le {date} à {heure} ")
            if type_reunion == 'presentielle':
                msg.body += f"\nLieu: {lieu}"
            elif type_reunion == 'meet':
                msg.body += f"\nLien Meet: {lien_meet}"
            mail.send(msg)

        return jsonify({'message': 'Réunion ajoutée avec succès et invitations envoyées'}), 201
    except Exception as e:
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500






@app.route('/reunions', methods=['GET'])
def get_reunions():
    try:
        reunions = Reunion.query.all()
        return jsonify([reunion.serialize() for reunion in reunions]), 200
    except Exception as e:
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500






@app.route('/reunions/<int:reunion_id>/participants/<int:user_id>/presence', methods=['PUT'])
def update_presence(reunion_id, user_id):
    data = request.get_json()
    presence = data.get('presence')

    if presence is None:
        return jsonify({'error': 'Presence is required'}), 400

    user_reunion = UserReunion.query.filter_by(reunion_id=reunion_id, user_id=user_id).first()

    if not user_reunion:
        return jsonify({'error': 'User or Reunion not found'}), 404

    user_reunion.presence = presence
    db.session.commit()

    return jsonify({'message': 'Presence updated successfully'}), 200




@app.route('/reunions/<int:reunion_id>', methods=['PUT'])
def update_reunion_status(reunion_id):
    data = request.get_json()
    reunion = Reunion.query.get(reunion_id)
    if 'statut' in data:
        reunion.statut = data['statut']
    db.session.commit()
    return jsonify(reunion.serialize())



@app.route('/conseillersReunions', methods=['GET'])
def get_conseillers_reunions():
    # Récupère tous les utilisateurs dont le rôle a le nom 'conseiller'
    conseillers = Users.query.join(Role).filter(Role.name == 'conseiller').all()
    # Sérialise les utilisateurs
    serialized_conseillers = [user.serialize() for user in conseillers]
    return jsonify(serialized_conseillers)



@app.route('/conseillersReunionsEmails', methods=['GET'])
def get_conseillers_emails():
    # Récupère les emails des utilisateurs dont le rôle a le nom 'conseiller'
    conseillers_emails = Users.query\
        .join(Role)\
        .filter(Role.name == 'conseiller')\
        .with_entities(Users.email)\
        .all()
    
    # Formatte les résultats en une liste d'emails
    emails = [email[0] for email in conseillers_emails]
    
    return jsonify(emails)




# UPLOAD_FOLDER = 'static/pdfRapport'
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


UPLOAD_PVR = 'static/PV'
app.config['UPLOAD_PVR'] = UPLOAD_PVR

@app.route('/reunions/<int:reunion_id>/upload_pv', methods=['POST'])
def upload_pv(reunion_id):
    if 'pv_file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['pv_file']
    
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_PVR'], filename)
        file.save(file_path)
        
        reunion = Reunion.query.get(reunion_id)
        if not reunion:
            return jsonify({'message': 'Réunion non trouvée'}), 404
        
        reunion.pv_path = file_path
        db.session.commit()
        
        # Envoyer un e-mail de notification à tous les participants
        participants_emails = [user.user.email for user in reunion.users]
        send_email_notification(participants_emails, reunion)
        
        return jsonify({'message': 'PV uploaded and notification sent successfully'}), 200

    return jsonify({"message": "Unknown error occurred"}), 500

def send_email_notification(participants_emails, reunion):
    with app.app_context():
        subject = "Nouveau procès-verbal disponible"
        body = f"Le procès-verbal de la réunion du {reunion.date.strftime('%d/%m/%Y')} à {reunion.heure.strftime('%H:%M')} est désormais disponible."
        
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=participants_emails)
        msg.body = body
        
        mail.send(msg)




@app.route('/reunions/<int:reunion_id>/participants', methods=['GET'])
def get_reunion_participants(reunion_id):
    participants = UserReunion.query.filter_by(reunion_id=reunion_id).all()
    return jsonify([participant.serialize() for participant in participants])




@app.route('/reunions/<int:reunion_id>/delete_pv', methods=['DELETE'])
def delete_pv(reunion_id):
    try:
        reunion = Reunion.query.get(reunion_id)
        if not reunion:
            return jsonify({'error': 'Reunion not found'}), 404

        pv_path = reunion.pv_path
        if not pv_path:
            return jsonify({'error': 'No PV to delete'}), 400

        # Supprimer le fichier du système de fichiers
        try:
            os.remove(pv_path)
        except OSError as e:
            return jsonify({'error': f'Error deleting file: {str(e)}'}), 500

        # Mettre à jour la base de données pour supprimer la référence au PV
        reunion.pv_path = None
        db.session.commit()

        return jsonify({'message': 'PV deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500
    

if __name__ == '__main__':
    app.run(debug=True, port=5000)

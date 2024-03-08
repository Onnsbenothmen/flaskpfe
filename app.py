from functools import wraps
from sqlalchemy.sql import func
from . import app, db
from .models import Users, Instance, Role,ProgrammeVisite,db,Reunion,ArchivedUser,Resultat

from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
from datetime import datetime, timezone, timedelta
from werkzeug.utils import secure_filename
import os
from flask_mail import Mail, Message
from flask_jwt_extended import jwt_required, create_access_token, JWTManager, get_jwt_identity, get_jwt, create_refresh_token
import json
from flask import Flask, jsonify, request, make_response,redirect, url_for
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
app.config['JWT_SECRET_KEY'] = secret_key  # Configurez la clé secrète JWT
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
@app.route('/signup', methods=['POST'])
def signup():

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

        # Obtenir l'ID du rôle président
        president_role_id = None
        for role in roles_data:
            if role["name"] == "président":
                president_role_id = role["id"]
                break

        # Créer un nouvel utilisateur avec le rôle par défaut président
        new_user = Users(
            firstName=first_name,
            lastName=last_name,
            email=email,
            password=hashed_password,
            phoneNumber=phone_number,
            address=address,
            profile_image=filename,
            role_id=president_role_id  # Utiliser l'ID du rôle président par défaut
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Utilisateur enregistré avec succès"}), 201
    else:
        return jsonify({"message": "Extension de fichier non autorisée"}), 400
# Route de connexion

@app.route("/login", methods=["POST"])
def login():
    auth = request.json
    email = auth.get("email")  # Retrieve email from the request
    password = auth.get("password")  # Retrieve password from the request

    # Log connection data in the console
    print(f"Email: {email}, Password: {password}")

    # Find the user in the database by email
    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Check password
    if check_password_hash(user.password, password):
        # Check if the user account is archived
        if user.is_archived:
            return jsonify({"message": "Your account is archived. Please contact the administrator."}), 401
        # Proceed with login if the user account is not archived
        token_payload = {
            'id': user.id,
            'role': user.role.name if user.role else None,
            'email': user.email,
            'firstName': user.firstName,
            'lastName': user.lastName,
            "phoneNumber": user.phoneNumber,
            "address": user.address,
            "profile_image": user.profile_image       # Return profile image binary data
        }
        # Generate JWT token
        token = create_access_token(identity=token_payload)
        
        # Return user profile information with the access token
        return jsonify({"token": token, "profile": token_payload}), 200
    else:
        # Return error message if credentials do not match
        return jsonify({'message': 'Please check your credentials'}), 401




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
            users = Users.query.join(Role).filter(Role.name == role_name).filter_by(is_archived=False).all()
            if role_name == 'président':
                serialized_users = [{"email": user.email} for user in users]
            else:
                serialized_users = [user.serialize() for user in users]
            return jsonify({"data": serialized_users}), 200
        else:
            users = Users.query.filter_by(is_archived=False).all()  # Exclure les utilisateurs archivés
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
    # Query the Users model to retrieve archived users
    archived_users = Users.query.filter_by(is_archived=True).all()

    # Serialize the archived user objects to JSON format
    serialized_users = [user.serialize() for user in archived_users]

    # Return the serialized users as a JSON response
    return jsonify(serialized_users)




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
    try:
        data = request.json
        president_email = data.get("president_email")
        instance_name = data.get("instance_name")
        nombre_conseille = data.get("nombre_conseille")
        gouvernement = data.get("gouvernement")
        ville = data.get("ville")
        active = data.get("active")

        if president_email and instance_name and ville:
            instance = Instance.query.filter_by(president_email=president_email).first()
            if instance:
                return make_response({"message": "Instance already exists"}, 200)

            new_instance = Instance(
                president_email=president_email,
                instance_name=instance_name,
                nombre_conseille=nombre_conseille,
                gouvernement=gouvernement,
                ville=ville,
                active=active if active is not None else True,
            )
            db.session.add(new_instance)
            db.session.commit()

            send_email_to_president(president_email, instance_name, ville)

            return make_response({"message": "Instance Created and Email sent to President"}, 201)

        return make_response({"message": "Missing required fields"}, 400)
    except Exception as e:
        print(e)
        return make_response({"message": f"Error: {str(e)}"}, 500)


@app.route('/instances/<int:id>', methods=['PUT'])
def update_instance(id):
    try:
        instance = Instance.query.get_or_404(id)
        data = request.json
        instance.president_email = data.get('president_email', instance.president_email)
        instance.instance_name = data.get('instance_name', instance.instance_name)
        instance.nombre_conseille = data.get('nombre_conseille', instance.nombre_conseille)
        instance.gouvernement = data.get('gouvernement', instance.gouvernement)
        instance.ville = data.get('ville', instance.ville)
        instance.active = data.get('active', instance.active)
        db.session.commit()
        return instance.serialize(), 200
    except Exception as e:
        print(e)
        return make_response({"message": f"Error: {str(e)}"}, 500)

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

def send_email_to_president(president_email, instance_name, ville):
    try:
        # Lien d'inscription
        signup_link = "http://localhost:3000/signup"

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
    except Exception as e:
        print("Error sending email:", e)



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

from flask import request, jsonify

# Créer une réunion
@app.route('/reunions', methods=['POST'])
def create_reunion():
    data = request.json
    type_reunion = data.get('type_reunion')  # Récupérer le type de réunion depuis les données JSON
    new_reunion = Reunion(
        type_reunion=type_reunion,  # Enregistrer le type de réunion dans la base de données
        date=data.get('date'),
        heure=data.get('heure'),
        lieu=data.get('lieu'),
        ordre_du_jour=data.get('ordre_du_jour'),
        statut=data.get('statut')
    )
    db.session.add(new_reunion)
    db.session.commit()
    return jsonify({'message': 'Reunion created successfully'}), 201


# Obtenir toutes les réunions
@app.route('/reunions', methods=['GET'])
def get_all_reunions():
    reunions = Reunion.query.all()
    return jsonify([reunion.serialize() for reunion in reunions]), 200

# Obtenir une réunion par ID
@app.route('/reunions/<int:reunion_id>', methods=['GET'])
def get_reunion_by_id(reunion_id):
    reunion = Reunion.query.get(reunion_id)
    if not reunion:
        return jsonify({'message': 'Reunion not found'}), 404
    return jsonify(reunion.serialize()), 200

# Mettre à jour une réunion
@app.route('/reunions/<int:reunion_id>', methods=['PUT'])
def update_reunion(reunion_id):
    data = request.json
    reunion = Reunion.query.get(reunion_id)
    if not reunion:
        return jsonify({'message': 'Reunion not found'}), 404
    reunion.type_reunion = data['type_reunion']
    reunion.date = data['date']
    reunion.heure = data['heure']
    reunion.lieu = data['lieu']
    reunion.ordre_du_jour = data['ordre_du_jour']
    reunion.statut = data['statut']
    db.session.commit()
    return jsonify({'message': 'Reunion updated successfully'}), 200

# Supprimer une réunion
@app.route('/reunions/<int:reunion_id>', methods=['DELETE'])
def delete_reunion(reunion_id):
    reunion = Reunion.query.get(reunion_id)
    if not reunion:
        return jsonify({'message': 'Reunion not found'}), 404
    db.session.delete(reunion)
    db.session.commit()
    return jsonify({'message': 'Reunion deleted successfully'}), 200

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
    
    
    
    
    






if __name__ == '__main__':
    app.run(debug=True, port=5000)

from functools import wraps
from sqlalchemy.sql import func
from . import app, db
from .models import Users, Instance, Role,ProgrammeVisite,db,Reunion
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
from flask import Flask, jsonify, request, make_response, flash,send_file
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

from flask import send_from_directory


#app = Flask(__name__)
#CORS(app)


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

    # Afficher les données de connexion dans la console
    print(f"Email: {email}, Password: {password}")

    # Recherche de l'utilisateur dans la base de données par son email
    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Utilisateur non trouvé"}), 404

    # Vérification du mot de passe
    if check_password_hash(user.password, password):
        token_payload = {
            'id': user.id,
            'role': user.role.name if user.role else None,
            'email': user.email,
            'firstName': user.firstName,
            'lastName': user.lastName,
            "phoneNumber": user.phoneNumber,
            "address": user.address,
            "profile_image": user.profile_image       # On renvoie les données binaires de l'image de profil
        }
        if user.role.name == 'président':
            title = 'Ajouter un utilisateur'
        else:
            title = 'Ajouter président'
        token = create_access_token(identity=token_payload)  # Générer le token JWT
        
        # Retourner les informations du profil de l'utilisateur avec le token d'accès
        return jsonify({"token": token, "profile": token_payload}), 200
    else:
        # Si les identifiants ne correspondent pas, renvoyer un message d'erreur
        return jsonify({'message': 'Veuillez vérifier vos identifiants'}), 401


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

@app.route("/admin_dashboard")
@token_required
def admin_dashboard(current_user):
    if current_user.role.name != 'admin':
        return make_response({'message': 'Permission denied'}, 403)


@app.route("/conseille")
@token_required
def conseille_dashboard(current_user):
    if current_user.role.name != 'Conseille Local':
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

@app.route("/users", methods=["GET"])
def get_all_users():
    try:
        role_name = request.args.get('role')
        if role_name:
            users = Users.query.join(Role).filter(Role.name == role_name).all()
            if role_name == 'président':
                serialized_users = [{"email": user.email} for user in users]
            else:
                serialized_users = [user.serialize() for user in users]
            return jsonify({"data": serialized_users}), 200
        else:
            users = Users.query.all()
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
        instance_name = data.get("instance_name")  # Modifier le nom de la variable pour refléter le changement
        ville = data.get("ville")  # Récupérez la ville depuis les données JSON
        active = data.get("active")
        created_at = data.get("created_at")

        if president_email and instance_name and ville:  # Assurez-vous que tous les champs requis sont présents
            instance = Instance.query.filter_by(president_email=president_email).first()
            if instance:
                return make_response({"message": "Instance already exists"}, 200)

            # Créez une nouvelle instance avec la ville
            new_instance = Instance(
                president_email=president_email,
                instance_name=instance_name,  # Utiliser le nouveau nom de l'instance
                ville=ville,
                active=active if active is not None else True,
                created_at=created_at
            )
            db.session.add(new_instance)
            db.session.commit()

            # Envoyez un e-mail au président avec le nom de l'instance
            send_email_to_president(president_email, instance_name, ville)  # Passer le nom de l'instance

            return make_response({"message": "Instance Created and Email sent to President"}, 201)

        return make_response({"message": "Missing required fields"}, 400)
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


@app.route('/instances/<int:id>', methods=['PUT'])
def update_instance(id):
    instance = Instance.query.get_or_404(id)
    data = request.json
    instance.president_email = data.get('president_email', instance.president_email)
    instance.instance_name = data.get('instance_name', instance.instance_name)
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

def send_email_to_president(president_email, instance_name, ville):
    try:
        # Créer le message d'e-mail
        message = Message(subject="Nouvelle instance créée",
                          recipients=[president_email],
                          body=f"Bienvenue Monsieur/Madame le président,\n\n"
                               f"Une nouvelle instance a été créée pour votre gestion. Les détails sont les suivants :\n\n"
                               f"Nom de l'instance : {instance_name}\n"
                               f"Ville : {ville}\n\n"
                               f"Merci de prendre les mesures nécessaires.\n\n"
                               f"Cordialement,\nVotre application")

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



""" @app.route("/refresh_token", methods=["POST"])
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
        return jsonify({"message": "Unable to refresh token"}), 5 """


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
    new_reunion = Reunion(
        type_reunion=data['type_reunion'],
        date=data['date'],
        heure=data['heure'],
        lieu=data['lieu'],
        ordre_du_jour=data['ordre_du_jour'],
        statut=data['statut']
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

serializer = URLSafeTimedSerializer(app.secret_key)

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.json.get('email')
    # Vérifiez si l'e-mail existe dans votre base de données ou système d'authentification
    # Générez un token de réinitialisation du mot de passe
    token = serializer.dumps(email)
    # Envoyez l'e-mail avec le lien contenant le token de réinitialisation
    # Vous pouvez utiliser Flask-Mail ou un autre service pour envoyer des e-mails
    return jsonify({'message': 'Un e-mail de réinitialisation a été envoyé.'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)

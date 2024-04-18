from functools import wraps
from sqlalchemy.sql import func
from . import app, db
from .models import Users, Instance, Role,AdminPublique,ProgrammeVisite, ProgrammeConseiller,ProgrammeAdmin,ConseillerLocal,db
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
from flask import Flask, jsonify, request, make_response, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from .models import ConseillerLocal, db, AdminPublique,Users, ProgrammeVisite, ProgrammeConseiller,ProgrammeAdmin,Resultat

from flask_sqlalchemy import SQLAlchemy
import jwt
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from . import models
from . import app

app = Flask(__name__)
CORS(app)


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
db.init_app(app)

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



# Route pour l'inscription d'un nouvel utilisateur administrateur
@app.route('/signup_admin', methods=['POST'])
def signup_admin():
    # Vérifier si une image est présente dans la requête
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['file']
    # Vérifier si un fichier a été sélectionné pour le téléchargement
    if file.filename == '':
        return jsonify({"message": "No image selected for uploading"}), 400
    
    # Vérifier si les données de formulaire sont présentes
    if 'firstName' not in request.form or 'lastName' not in request.form or 'email' not in request.form or 'password' not in request.form or 'directeur' not in request.form:
        return jsonify({"message": "Missing form data"}), 400
    
    # Extraire les données du formulaire
    firstName = request.form['firstName']
    lastName = request.form['lastName']
    password = request.form['password']
    email = request.form['email']
    directeur = request.form['directeur']
    
    # Enregistrer le fichier sur le serveur
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Hasher le mot de passe avant de l'enregistrer dans la base de données
        hashed_password = generate_password_hash(password)
        
        # Créer un nouvel utilisateur avec les données du formulaire et le nom de fichier de l'image
        new_President = AdminPublique(firstName=firstName, lastName=lastName, password=hashed_password, email=email, directeur=directeur, profile_image=filename)
        db.session.add(new_President)
        db.session.commit()

        return jsonify({"message": "President created successfully"}), 200
    else:
        return jsonify({"message": "Allowed image types are - png, jpg, jpeg, gif"}), 400

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
    if current_user.role.name != 'admin':
        return make_response({'message': 'Permission denied'}, 403)
    # Logique pour le tableau de bord de l'admin

@app.route("/users", methods=["GET"])
def get_all_users():
    try:
        # Récupération de tous les utilisateurs de la base de données
        users = Users.query.all()

        # Sérialisation des données des utilisateurs
        serialized_users = [user.serialize() for user in users]

        return jsonify({"data": serialized_users}), 200

    except Exception as e:
        print(e)
        return make_response({"message": f"Erreur: {str(e)}"}, 500)
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

@app.route('/profile/<user_email>')
@jwt_required()
def my_profile(user_email):
    current_user_email = get_jwt_identity()
    if user_email != current_user_email:
        return jsonify({"error": "Unauthorized Access"}), 401
    
    user = User.query.filter_by(email=user_email).first()
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
    
    users = User.query.all()
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
    user = Users.query.filter_by(id=current_user_id).first()  # Assurez-vous de remplacer current_user_id par l'ID de l'utilisateur connecté

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

@app.route("/admins", methods=["GET"])
def get_all_admins():
    try:
        # Fetch all admins
        admins = AdminPublique.query.order_by(AdminPublique.id).all()

        # Print debug information
        print("All Admins:", admins)

        # Serialize admin data
        serialized_admins = [admin.serialize() for admin in admins]  # Call the serialize method

        return jsonify({"data": serialized_admins}), 200

    except Exception as e:
        print(e)
        return make_response({"message": f"Error: {str(e)}"}, 500)


@app.route("/adminpublique/<int:admin_id>", methods=["GET"])
def get_admin(admin_id):
    try:
        admin = AdminPublique.query.get(admin_id)
        if not admin:
            return make_response({"message": f"Admin with id {admin_id} not found"}, 404)

        return jsonify(admin.serialize()), 200

    except Exception as e:
        print(e)
        return make_response({"message": "Unable to get admin"}, 500)


@app.route("/adminpublique/<int:admin_id>", methods=["PUT"])
def update_admin(admin_id):
    try:
        admin = AdminPublique.query.get(admin_id)
        if not admin:
            return make_response({"message": f"Admin with id {admin_id} not found"}, 404)

        # Update the admin fields
        admin.firstName = request.form.get('firstName')
        admin.lastName = request.form.get('lastName')
        admin.email = request.form.get('email')
        admin.directeur = request.form.get('directeur')

        # Check if a file was uploaded in the request
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Update the profile image path in the database
                admin.profile_image = filename

        db.session.commit()

        return jsonify({"message": "Admin updated successfully"}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to update admin"}, 500)

@app.route("/adminpublique/<int:admin_id>", methods=["DELETE"])
def delete_admin(admin_id):
    try:
        admin = AdminPublique.query.get(admin_id)
        if not admin:
            return make_response({"message": f"Admin with id {admin_id} not found"}, 404)

        db.session.delete(admin)
        db.session.commit()

        return jsonify({"message": "Admin deleted successfully"}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to delete admin"}, 500)

@app.route('/api/conseillers-emails', methods=['GET'])
def get_conseillers_emails():
    # Récupérer les emails des conseillers locaux depuis la base de données
    conseillers = ConseillerLocal.query.all()
    emails = [conseiller.email for conseiller in conseillers]
    return jsonify(emails)

@app.route('/api/admins-emails', methods=['GET'])
def get_admins_emails():
    # Récupérer les emails des administrateurs publics depuis la base de données
    admins = AdminPublique.query.all()
    emails = [admin.email for admin in admins]
    return jsonify(emails)


@app.route('/api/create-evaluation-program', methods=['POST'])
def create_evaluation_program():
    try:
        data = request.json
        periode = data.get('periode')
        criteres_evaluation = data.get('criteres_evaluation')
        lieu = data.get('lieu')
        description = data.get('description')
        contacts_urgence = data.get('contacts_urgence')
        admin_email = data.get('adminEmail')
        conseiller_emails = data.get('conseillerEmails')
        email_subject = data.get('email_subject')
        email_content = data.get('email_content')

        # Créer un nouveau ProgrammeVisite
        nouveau_programme = ProgrammeVisite(periode_debut=periode[0], periode_fin=periode[1], criteres_evaluation=criteres_evaluation, lieu=lieu, description=description, contacts_urgence=contacts_urgence)
        db.session.add(nouveau_programme)

        # Récupérer les AdminPublique par email
        admins = AdminPublique.query.filter(AdminPublique.email == admin_email).all()

        # Créer des entrées ProgrammeAdmin pour chaque admin
        for admin in admins:
            programme_admin = ProgrammeAdmin(
                programme=nouveau_programme,
                admin=admin
            )
            db.session.add(programme_admin)

        db.session.commit()

        # Récupérer les ConseillersLocaux par email
        conseillers = ConseillerLocal.query.filter(ConseillerLocal.email.in_(conseiller_emails)).all()

        # Créer des entrées ProgrammeConseiller pour chaque conseiller
        for conseiller in conseillers:
            programme_conseiller = ProgrammeConseiller(
                programme=nouveau_programme,
                conseiller=conseiller
            )
            db.session.add(programme_conseiller)

        db.session.commit()

        # Envoyer un email aux administrateurs publics et aux conseillers
        send_email(admin_email, email_subject, email_content)
        for conseiller_email in conseiller_emails:
            send_email(conseiller_email, email_subject, email_content)

        return jsonify({'message': 'Nouveaux programmes d\'évaluation créés avec succès et e-mails envoyés'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500



def send_email(to_email, subject, content):
    # Configurer les détails du serveur SMTP
    smtp_server = 'smtp.googlemail.com'
    smtp_port = 587
    smtp_username = 'nourgarali12345@gmail.com'
    smtp_password = 'tmok wtxn cbia xobx'

    # Créer un objet MIMEText avec le contenu de l'e-mail
    message = MIMEMultipart()
    message['From'] = smtp_username
    message['To'] = to_email
    message['Subject'] = subject
    message.attach(MIMEText(content, 'plain'))

    # Établir une connexion avec le serveur SMTP
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()

    # Se connecter au serveur SMTP
    server.login(smtp_username, smtp_password)

    # Envoyer l'e-mail
    server.send_message(message)

    # Fermer la connexion
    server.quit()
    
    
@app.route('/generate-email', methods=['POST'])
def generate_email():
    # Récupérer les données du formulaire
    periode = request.form.get('periode')
    criteres_evaluation = request.form.get('criteres_evaluation')
    lieu = request.form.get('lieu')
    description = request.form.get('description')
    contacts_urgence = request.form.get('contacts_urgence')
    admin_email = request.form.get('adminEmail')
    conseiller_emails = request.form.getlist('conseillerEmails')

    # Générer le sujet et le contenu de l'e-mail
    email_subject = f"Programme de visite d'évaluation - {periode}"
    email_content = f"""Bonjour,

    Vous êtes invités à participer au programme de visite d'évaluation du {periode}. Les critères d'évaluation sont les suivants : {criteres_evaluation}.
    
    Lieu de visite : {lieu}
    Description : {description}
    Contacts d'urgence : {contacts_urgence}

    Cordialement,"""

    # Retourner le sujet et le contenu de l'e-mail générés
    return jsonify({
        "email_subject": email_subject,
        "email_content": email_content,
        "admin_email": admin_email,
        "conseiller_emails": conseiller_emails
    })
    
# -----------------------------------------------------Resultat------------------------------------------------------------
@app.route('/resultats', methods=['POST'])
def create_resultat():
    data = request.get_json()

    new_resultat = Resultat(
        observations=data.get('observations'),
        evaluations=data.get('evaluations'),
        recommendations=data.get('recommendations'),
        conseiller_id=data.get('conseiller_id'),
        programme_id=data.get('programme_id'),
    )

    db.session.add(new_resultat)
    db.session.commit()

    return jsonify(new_resultat.serialize()), 201
# --------------------------------------Conseilleur local Visite-----------------------------------------------------

@app.route('/api/list-programs-for-conseiller/<int:conseiller_id>', methods=['GET'])
def list_programs_for_conseiller(conseiller_id):
    try:
        # Rechercher le conseiller par ID
        conseiller = ConseillerLocal.query.get(conseiller_id)
        
        if conseiller is None:
            return jsonify({'error': 'Conseiller introuvable'}), 404

        # Récupérer les programmes de visite associés à ce conseiller
        programmes = [
            {
                'programme_id': programme.programme_id,
                'periode_debut': programme.programme.periode_debut,
                'periode_fin': programme.programme.periode_fin,
                'criteres_evaluation': programme.programme.criteres_evaluation,
                'lieu': programme.programme.lieu,
                'description': programme.programme.description,
                'contacts_urgence': programme.programme.contacts_urgence,
                'documents_joints': programme.programme.documents_joints,
                'created_at': programme.programme.created_at
            }
            for programme in conseiller.programmes_visite
        ]

        return jsonify({'programs': programmes}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ------------------------------------------ AdminPublique ------------------------------------------------------------


@app.route('/api/list-programs-for-admin/<int:admin_id>', methods=['GET'])
def list_programs_for_admin(admin_id):
    try:
        # Rechercher l'administrateur public par ID
        admin = AdminPublique.query.get(admin_id)
        
        if admin is None:
            return jsonify({'error': 'Administrateur public introuvable'}), 404

        # Récupérer les programmes de visite associés à cet administrateur
        programmes = [
            {
                'programme_id': programme.programme_id,
                'periode_debut': programme.programme.periode_debut,
                'periode_fin': programme.programme.periode_fin,
                'criteres_evaluation': programme.programme.criteres_evaluation,
                'lieu': programme.programme.lieu,
                'description': programme.programme.description,
                'contacts_urgence': programme.programme.contacts_urgence,
                'documents_joints': programme.programme.documents_joints,
                'created_at': programme.programme.created_at
            }
            for programme in admin.programmes_visite
        ]

        return jsonify({'programs': programmes}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# ------------------------------------------------lister tout les programmes de visite pour president--------------------------------------------------------

@app.route('/api/list-all-programs', methods=['GET'])
def list_all_programs():
    try:
        programs = ProgrammeVisite.query.all()
        serialized_programs = [program.serialize() for program in programs]
        return jsonify({'programs': serialized_programs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/signup_conseilleur', methods=['POST'])
def signup_conseilleur():
    try:
        data = request.form
        firstName = data.get("firstName")
        lastName = data.get("lastName")
        password = data.get("password")
        email = data.get("email")
        profile_image = request.files.get('file')

        # Vérification des données obligatoires
        if not (firstName and lastName and password and email and profile_image):
            return jsonify({"message": "Missing form data"}), 400

        # Enregistrement de l'image sur le serveur
        if profile_image and allowed_file(profile_image.filename):
            filename = secure_filename(profile_image.filename)
            profile_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return jsonify({"message": "Invalid image"}), 400

        # Hasher le mot de passe avant de l'enregistrer dans la base de données
        hashed_password = generate_password_hash(password)

        # Création d'un nouveau conseiller avec les données du formulaire et le nom de fichier de l'image
        new_conseilleur = ConseillerLocal(
            firstName=firstName,
            lastName=lastName,
            password=hashed_password,
            email=email,
            profile_image=filename
        )
        db.session.add(new_conseilleur)
        db.session.commit()

        return jsonify({"message": "Conseiller created successfully"}), 201
    except Exception as e:
        print("Error during signup:", str(e))
        return jsonify({"error": f"Error during signup: {str(e)}"}), 500


@app.route("/Conseilleur", methods=["GET"])
def get_all_Conseilleur():
    try:
        # Fetch all conseillerLocale
        all_Conseilleur = ConseillerLocal.query.all()

        # Print debug information
        print("All conseillerLocale:", all_Conseilleur)

        # Commit the transaction explicitly
        db.session.commit()

        # Serialize conseillerLocale data
        serialized_conseillerLocale = [conseillerLocale.serialize() for conseillerLocale in all_Conseilleur]  # Call the serialize method

        return jsonify({"data": serialized_conseillerLocale}), 200

    except Exception as e:
        print(e)
        # Rollback the transaction in case of an exception
        db.session.rollback()
        return make_response({"message": f"Error: {str(e)}"}, 500)

@app.route("/Conseilleur/<int:Conseilleur_id>", methods=["DELETE"])
def delete_Conseilleur(Conseilleur_id):
    try:
        # Fetch the Conseilleur
        Conseilleur_to_delete = ConseillerLocal.query.get(Conseilleur_id)
        if not Conseilleur_to_delete:
            return make_response({"message": f"conseillerLocale with id {Conseilleur_id} not found"}, 404)

        db.session.delete(Conseilleur_to_delete)
        db.session.commit()

        return make_response({"message": "conseillerLocale deleted successfully"}, 200)

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": f"Unable to delete conseillerLocale: {str(e)}"}, 500)

@app.route("/Conseilleur/<int:Conseilleur_id>", methods=["PUT"])
def update_Conseilleur(Conseilleur_id):
    try:
        # Fetch the Conseilleur_id
        Conseilleur_id_to_update = ConseillerLocal.query.get(Conseilleur_id)
        if not Conseilleur_id_to_update:
            return make_response({"message": f"conseillerLocale with id {Conseilleur_id} not found"}, 404)

        # Update the Conseilleur_id fields
        Conseilleur_id_to_update.firstName = request.form.get('firstName')
        Conseilleur_id_to_update.lastName = request.form.get('lastName')
        Conseilleur_id_to_update.email = request.form.get('email')

        # Check if a file was uploaded in the request
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Update the profile image path in the database
                Conseilleur_id_to_update.profile_image = filename

        db.session.commit()

        return jsonify({"message": "conseillerLocale updated successfully"}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to update conseillerLocale"}, 500)

if __name__ == '__main__':
    app.run(debug=True, port=5000)

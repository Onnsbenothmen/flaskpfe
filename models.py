from . import db
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import and_
from datetime import datetime



class Users(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=True)
    lastName = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(250), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    profile_image = db.Column(db.String(250))  # Champ pour l'image de profil
    nameAdminPublique = db.Column(db.String(100))
    role_id = db.Column(db.Integer, db.ForeignKey("Role.id"))
    role = db.relationship('Role', back_populates='users')
    programmes_visite = db.relationship('ProgrammeVisite', back_populates='user', cascade='all, delete-orphan')   
    phoneNumber = db.Column(db.String(20), nullable=True)  # Nouveau champ pour le numéro de téléphone
    address = db.Column(db.String(255), nullable=True)  # Nouveau champ pour l'adresse
    instance_id = db.Column(db.Integer, db.ForeignKey("instances.id"))
    instance = db.relationship('Instance', back_populates='users')
    verification_code = db.Column(db.String(10))  # Ajoutez cette ligne pour l'attribut verification_code
    is_archived = db.Column(db.Boolean, default=False)  # Nouveau champ pour indiquer si l'utilisateur est archivé
    is_active = db.Column(db.Boolean, default=False)  # Champ pour indiquer si l'utilisateur est actif
    reunions = db.relationship('UserReunion', back_populates='user')
    demandes_acces_info = db.relationship('DemandeAccesInfo', back_populates='user', foreign_keys='DemandeAccesInfo.user_id', cascade='all, delete-orphan')
    demandes_acces_info_directeur = db.relationship('DemandeAccesInfo', foreign_keys='DemandeAccesInfo.directeur_id', back_populates='directeur')
    Plainte = db.relationship('Plainte', back_populates='user', foreign_keys='Plainte.user_id', cascade='all, delete-orphan')
    Proposition = db.relationship('Proposition', back_populates='user', foreign_keys='Proposition.user_id', cascade='all, delete-orphan')
    birth_date = db.Column(db.Date, nullable=True)  # Champ pour la date de naissance
    cin = db.Column(db.String(20), unique=True, nullable=True)  # Champ pour le CIN
    situation_familiale = db.Column(db.String(100), nullable=True)  # Champ pour l'état
    ville = db.Column(db.String(100), nullable=True)  # Pas de virgule ici
    linkedin = db.Column(db.String(255))  # Pas de virgule ici
    lienFacebook = db.Column(db.String(255))  # Pas de virgule ici
    description_profil = db.Column(db.String(500))  # Pas de virgule ici
    
    def __repr__(self):
        return f'<User {self.firstName} {self.id}>'

    def serialize(self):
        role_name = self.role.name if self.role else None
        instance_name = self.instance.instance_name if self.instance else None
        nb_conseilles = self.instance.nombre_conseille if self.instance else None
        created_at_formatted = self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        birth_date = self.birth_date.strftime('%a, %d %b %Y %H:%M:%S GMT') if self.birth_date else None

        return {
            "id": self.id,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "email": self.email,
            "role_name": role_name,
            "created_at":  created_at_formatted,
            "profile_image": self.profile_image,
            "nameAdminPublique": self.nameAdminPublique,
            "phoneNumber": self.phoneNumber,  # Ajout du numéro de téléphone
            "address": self.address, # Ajout de l'adresse
            "is_archived": self.is_archived,
            "instance_name": instance_name,
            "birth_date": birth_date,  # Ajout de la date de naissance
            "nb_conseilles": nb_conseilles,  # Ajoutez le nombre de conseillers à la sérialisation de l'utilisateur
            "situation_familiale": self.situation_familiale,  # Ajout de l'état

            "cin": self.cin,  # Ajout du CIN
            "ville": self.ville,  # Ajout de la ville
            "linkedin": self.linkedin,  # Ajout de l'URL LinkedIn
            "lienFacebook": self.lienFacebook,  # Ajout de l'URL Facebook
            "description_profil": self.description_profil  # Ajout de la description de profil
        }
        

       


       
class Plainte(db.Model):
    __tablename__ = 'Plainte'
    id = db.Column(db.Integer, primary_key=True)
    titre = db.Column(db.String(500))
    description = db.Column(db.String(500), nullable=False)
    citoyen_email = db.Column(db.String(100), nullable=False)
    nom_citoyen = db.Column(db.String(500))
    prenom_citoyen = db.Column(db.String(500))
    nom_conseiller = db.Column(db.String(100), nullable=False)
    statut = db.Column(db.Boolean, default=False) 
    reponse = db.Column(db.String(500))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    user = db.relationship('Users', foreign_keys=[user_id], back_populates='Plainte')
    is_archived = db.Column(db.Boolean, default=False)
    type = db.Column(db.Boolean)

    def serialize(self):    
        return {
            'id': self.id,
            'titre': self.titre,
            'description': self.description,
            'citoyen_email': self.citoyen_email,
            'nom_citoyen': self.nom_citoyen,
            'prenom_citoyen':self.prenom_citoyen,
            'nom_conseiller': self.nom_conseiller,
            'statut':self.statut,
            'reponse':self.reponse,
            'created_at': self.created_at,
            'user_id': self.user_id,
            'is_archived': self.is_archived,
            'type': self.type

        }
        
        

class Proposition(db.Model):
    __tablename__ = 'Proposition'
    id = db.Column(db.Integer, primary_key=True)
    titre = db.Column(db.String(500))
    description = db.Column(db.String(500), nullable=False)
    citoyen_email = db.Column(db.String(100), nullable=False)
    nom_citoyen = db.Column(db.String(500))
    prenom_citoyen = db.Column(db.String(500))
    nom_conseiller = db.Column(db.String(100), nullable=False)
    statut = db.Column(db.Boolean, default=False) 
    reponse = db.Column(db.String(500))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    user = db.relationship('Users', foreign_keys=[user_id], back_populates='Proposition')
    is_archived = db.Column(db.Boolean, default=False)
    type = db.Column(db.Boolean)

    def serialize(self):    
        return {
            'id': self.id,
            'titre': self.titre,
            'description': self.description,
            'citoyen_email': self.citoyen_email,
            'nom_citoyen': self.nom_citoyen,
            'prenom_citoyen':self.prenom_citoyen,
            'nom_conseiller': self.nom_conseiller,
            'statut':self.statut,
            'reponse':self.reponse,
            'created_at': self.created_at,
            'user_id': self.user_id,
            'is_archived': self.is_archived,
            'type': self.type

        }
        
        
        
        
class DemandeAccesInfo(db.Model):
    __tablename__ = 'demande_acces_info'
    id = db.Column(db.Integer, primary_key=True)
    titre = db.Column(db.String(500))
    description = db.Column(db.String(500), nullable=False)
    citoyen_email = db.Column(db.String(100), nullable=False)
    nom_citoyen = db.Column(db.String(500))
    prenom_citoyen = db.Column(db.String(500))
    acceptee = db.Column(db.Boolean, default=False) 
    nom_conseiller = db.Column(db.String(100), nullable=False)
    nom_administration = db.Column(db.String(100), nullable=False)
    statut = db.Column(db.Boolean, default=False) 
    reponse = db.Column(db.String(500))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    directeur_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=True)
    user = db.relationship('Users', foreign_keys=[user_id], back_populates='demandes_acces_info')
    directeur = db.relationship('Users', foreign_keys=[directeur_id], back_populates='demandes_acces_info_directeur')
    is_archived = db.Column(db.Boolean, default=False)



    def serialize(self):
        return {
            'id': self.id,
            'titre': self.titre,
            'description': self.description,
            'citoyen_email': self.citoyen_email,
            'nom_citoyen': self.nom_citoyen,
            'prenom_citoyen':self.prenom_citoyen,
            'acceptee':self.acceptee,
            'nom_conseiller': self.nom_conseiller,
            'nom_administration': self.nom_administration,
            'statut':self.statut,
            'reponse':self.reponse,
            'created_at': self.created_at,
            'user_id': self.user_id,
            'directeur_id': self.directeur_id,
            'is_archived': self.is_archived
        }




        
        
        
class Instance(db.Model):
    __tablename__ = "instances"
    id = db.Column(db.Integer, primary_key=True)
    instance_name = db.Column(db.String(100), nullable=False)
    president_email = db.Column(db.String(100), nullable=False)
    nombre_conseille = db.Column(db.Integer)  # Ajout de la colonne pour le nombre de conseillers
    ville = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean, default=True)
    archived = db.Column(db.Boolean, default=False)  # Nouvelle colonne pour indiquer si l'instance est archivée
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    users = db.relationship('Users', back_populates='instance')


    def serialize(self):
        return {
            "id": self.id,
            "instance_name": self.instance_name,
            "president_email": self.president_email,
            "nombre_conseille": self.nombre_conseille,  # Ajout du nombre de conseillers
            "ville": self.ville,
            "active": self.active,
            "archived": self.archived,  # Ajout de la colonne "archived" à la sérialisation
            "created_at": self.created_at,
        }

class SentEmail(db.Model):
    __tablename__ = 'sent_emails'

    id = db.Column(db.Integer, primary_key=True)
    president_email = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ArchivedUser(db.Model):
    __tablename__ = 'archived_users'
    id = db.Column(db.Integer, primary_key=True)
    # Ajoutez d'autres colonnes au besoin
    
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'))  # Assurez-vous que 'users' est le bon nom de table
    user = db.relationship('Users', backref='archived_users')

    def __repr__(self):
        return f"<ArchivedUser id={self.id}>"


class Role(db.Model):
    __tablename__ = "Role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(250))
    users = db.relationship('Users', back_populates='role')
    
    def __repr__(self):
        return f'<Role {self.name}>'

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
        }



class ProgrammeVisite(db.Model):
    __tablename__ = "ProgrammeVisite"
    id = db.Column(db.Integer, primary_key=True)
    nomProgramme = db.Column(db.Text)
    periode_debut = db.Column(db.DateTime(timezone=True))
    periode_fin = db.Column(db.DateTime(timezone=True))
    criteres_evaluation = db.Column(db.String(500))
    lieu = db.Column(db.String(200))  
    nomAdminPublique = db.Column(db.String(200))  
    description = db.Column(db.Text)   
    contacts_urgence = db.Column(db.String(200))  
    documents_joints = db.Column(db.String(500))  
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    conseiller_email = db.Column(db.String(100))  
    statut = db.Column(db.String(50), default='Prévue', server_default='Prévue')  # Définir le statut par défaut
    admin_email = db.Column(db.String(100))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    user = db.relationship('Users', back_populates='programmes_visite')
    resultat = db.relationship('Resultat', back_populates='programme', uselist=False) 
    
    
    def serialize(self):
        return {
            'id': self.id,
            'nomProgramme': self.nomProgramme,
            'periode_debut': self.periode_debut.isoformat(),
            'periode_fin': self.periode_fin.isoformat(),
            'criteres_evaluation': self.criteres_evaluation,
            'lieu': self.lieu,
            'nomAdminPublique': self.nomAdminPublique,
            'description': self.description,
            'contacts_urgence': self.contacts_urgence,
            'conseiller_email': self.conseiller_email,
            'admin_email': self.admin_email,
            'statut':self.statut,
            'documents_joints': self.documents_joints,
            'created_at': self.created_at.isoformat(),
        }
        
    
        
class Resultat(db.Model):
    __tablename__ = 'Resultat'
    id = db.Column(db.Integer, primary_key=True)
    observations = db.Column(db.Text, nullable=False)
    evaluations = db.Column(db.Text, nullable=False)
    recommendations = db.Column(db.Text, nullable=False)
    rapportPdf = db.Column(db.LargeBinary)
    programme_id = db.Column(db.Integer, db.ForeignKey('ProgrammeVisite.id'), unique=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    programme = db.relationship("ProgrammeVisite", back_populates="resultat")

    
    def serialize(self):
        return {
            'id': self.id,
            'observations': self.observations,
            'evaluations': self.evaluations,
            'recommendations': self.recommendations,
            'rapportPdf': self.rapportPdf,
            'user_id': self.user_id,
            'programme_id': self.programme_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            
        }



class Reunion(db.Model):
    __tablename__ = 'Reunions'
    id = db.Column(db.Integer, primary_key=True)
    type_reunion = db.Column(db.String(20))
    lien_meet = db.Column(db.Text)
    date = db.Column(db.Date)
    heure = db.Column(db.Time)
    lieu = db.Column(db.String(250))
    ordre_du_jour = db.Column(db.Text)
    statut = db.Column(db.String(50), default='Prévue', server_default='Prévue')  # Définir le statut par défaut
    pv_path = db.Column(db.String(250))
    users = db.relationship('UserReunion', back_populates='reunion')


    def __repr__(self):
        return f'<Reunion {self.date} {self.heure}>'

    def serialize(self):
        return {
            "id": self.id,
            "type_reunion": self.type_reunion,
            "lien_meet": self.lien_meet,
            "date": self.date.isoformat(),
            "heure": self.heure.isoformat(),
            "lieu": self.lieu,
            "ordre_du_jour": self.ordre_du_jour,
            "statut": self.statut,
            "pv_path": self.pv_path,
            "participants": [ur.user.serialize() for ur in self.users]

        }
        
    
class UserReunion(db.Model):
    __tablename__ = 'user_reunion'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    reunion_id = db.Column(db.Integer, db.ForeignKey('Reunions.id'), nullable=False)
    presence = db.Column(db.Boolean, default=True)  # Ajouter ce champ pour marquer la présence
    user = db.relationship('Users', back_populates='reunions')
    reunion = db.relationship('Reunion', back_populates='users')

    def __repr__(self):
        return f'<UserReunion user_id={self.user_id} reunion_id={self.reunion_id}>'

    def serialize(self):
        return {
            "id": self.id,
            "user": self.user.serialize(),
            "reunion": self.reunion.serialize(),
            "presence": self.presence  # Ajouter la présence à la sérialisation
        }

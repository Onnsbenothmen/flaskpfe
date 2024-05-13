from . import db
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import and_


class Users(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
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
    reunions = db.relationship('Reunion', back_populates='user')
    verification_code = db.Column(db.String(10))  # Ajoutez cette ligne pour l'attribut verification_code
    is_archived = db.Column(db.Boolean, default=False)  # Nouveau champ pour indiquer si l'utilisateur est archivé



    def __repr__(self):
        return f'<User {self.firstName} {self.id}>'

    def serialize(self):
        role_name = self.role.name if self.role else None
        return {
            "id": self.id,
            "firstName": self.firstName,
            "lastName": self.lastName,
            "email": self.email,
            "role_name": role_name,
            "created_at": self.created_at,
            "profile_image": self.profile_image,
            "nameAdminPublique": self.nameAdminPublique,
            "phoneNumber": self.phoneNumber, 
            "address": self.address, # Ajout de l'adresse de AdminPublique
            "is_archived": self.is_archived
        }



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

class Instance(db.Model):
    __tablename__ = "instances"
    id = db.Column(db.Integer, primary_key=True)
    president_email = db.Column(db.String(100), nullable=False)
    instance_name = db.Column(db.String(100), nullable=False)
    nombre_conseille = db.Column(db.Integer)  # Ajout de la colonne pour le nombre de conseillers
    gouvernement = db.Column(db.String(100))  # Ajout de la colonne pour le gouvernement
    ville = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    users = db.relationship('Users', back_populates='instance')

    def serialize(self):
        return {
            "id": self.id,
            "president_email": self.president_email,
            "instance_name": self.instance_name,
            "nombre_conseille": self.nombre_conseille,  # Ajout du nombre de conseillers
            "gouvernement": self.gouvernement,  # Ajout du gouvernement
            "ville": self.ville,
            "active": self.active,
            "created_at": self.created_at,
        }

class ProgrammeVisite(db.Model):
    __tablename__ = "ProgrammeVisite"
    id = db.Column(db.Integer, primary_key=True)
    nomProgramme = db.Column(db.Text)
    periode_debut = db.Column(db.DateTime(timezone=True), nullable=False)
    periode_fin = db.Column(db.DateTime(timezone=True), nullable=False)
    criteres_evaluation = db.Column(db.String(500), nullable=False)
    lieu = db.Column(db.String(200))  
    nomAdminPublique = db.Column(db.String(200))  
    description = db.Column(db.Text)   
    contacts_urgence = db.Column(db.String(200))  
    documents_joints = db.Column(db.String(500))  
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    conseiller_email = db.Column(db.String(100), nullable=False)  
    admin_email = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    user = db.relationship('Users', back_populates='programmes_visite')
    resultat = db.relationship('Resultat', back_populates='programme', uselist=False)  # Nouvelle relation
    
    
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
    statut = db.Column(db.String(20))
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
            'statut':self.statut,
            'user_id': self.user_id,
            'programme_id': self.programme_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            
        }

class Reunion(db.Model):
    __tablename__ = 'Reunion'
    id = db.Column(db.Integer, primary_key=True)
    type_reunion = db.Column(db.String(20))
    date = db.Column(db.Date)
    heure = db.Column(db.Time)
    lieu = db.Column(db.String(100))
    ordre_du_jour = db.Column(db.Text)
    statut = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"))  # Clé étrangère vers Users

    # Relation avec Users
    user = db.relationship('Users', back_populates='reunions')


    def serialize(self):
        serialized_data = {
            'id': self.id,
            'type_reunion': self.type_reunion,
            'date': self.date.isoformat() if self.date else None,
            'heure': self.heure.isoformat() if self.heure else None,
            'lieu': self.lieu,
            'ordre_du_jour': self.ordre_du_jour,
            'statut': self.statut,
            'user': self.user.serialize() if self.user else None
        }
        return serialized_data

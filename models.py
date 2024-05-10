from . import db
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

class Users(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    profile_image = db.Column(db.String(250))  # Champ pour l'image de profil
    role_id = db.Column(db.Integer, db.ForeignKey("Role.id"))
    role = db.relationship('Role', back_populates='users')
    programmes_visite = db.relationship('ProgrammeVisite', back_populates='users', cascade='all, delete-orphan')
    phoneNumber = db.Column(db.String(20), nullable=True)  # Nouveau champ pour le numéro de téléphone
    address = db.Column(db.String(255), nullable=True)  # Nouveau champ pour l'adresse
    instance_id = db.Column(db.Integer, db.ForeignKey("instances.id"))
    instance = db.relationship('Instance', back_populates='users')
    reunions = db.relationship('Reunion', back_populates='user')


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
            "phoneNumber": self.phoneNumber,  # Ajout du numéro de téléphone
            "address": self.address  # Ajout de l'adresse
        }

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
    ville = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    users = db.relationship('Users', back_populates='instance')


    def serialize(self):
        return {
            "id": self.id,
            "president_email": self.president_email,
            "instance_name": self.instance_name,
            "ville": self.ville,
            "active": self.active,
            "created_at": self.created_at,
        }

class ProgrammeVisite(db.Model):
    __tablename__ = "ProgrammeVisite"
    id = db.Column(db.Integer, primary_key=True)
    periode_debut = db.Column(db.DateTime(timezone=True), nullable=False)
    periode_fin = db.Column(db.DateTime(timezone=True), nullable=False)
    criteres_evaluation = db.Column(db.String(500), nullable=False)
    lieu = db.Column(db.String(200))  
    description = db.Column(db.Text)   
    contacts_urgence = db.Column(db.String(200))  
    documents_joints = db.Column(db.String(500))  
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    users = db.relationship('Users', back_populates='programmes_visite')
    resultats = db.relationship('Resultat', back_populates='programme')
    
    def serialize(self):
        return {
            'id': self.id,
            'periode_debut': self.periode_debut.isoformat(),
            'periode_fin': self.periode_fin.isoformat(),
            'criteres_evaluation': self.criteres_evaluation,
            'lieu': self.lieu,
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
    programme_id = db.Column(db.Integer, db.ForeignKey('ProgrammeVisite.id'))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    programme = db.relationship("ProgrammeVisite", back_populates="resultats")
    

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
        return {
            'id': self.id,
            'type_reunion': self.type_reunion,
            'date': self.date.isoformat(),
            'heure': self.heure.isoformat(),
            'lieu': self.lieu,
            'ordre_du_jour': self.ordre_du_jour,
            'statut': self.statut,
            'user': self.user.serialize() if self.user else None  # Sérialiser l'utilisateur associé à la réunion

        }

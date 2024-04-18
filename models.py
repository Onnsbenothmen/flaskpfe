from . import db
from sqlalchemy.sql import func

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
    admin_publique = db.relationship('AdminPublique', back_populates='users')
    conseiller_local = db.relationship('ConseillerLocal', back_populates='users')
    programmes_visite = db.relationship('ProgrammeVisite', back_populates='users', cascade='all, delete-orphan')
    phoneNumber = db.Column(db.String(20), nullable=True)  # Nouveau champ pour le numéro de téléphone
    address = db.Column(db.String(255), nullable=True)  # Nouveau champ pour l'adresse

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
    council_name = db.Column(db.String(100), nullable=False)
    ville = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def serialize(self):
        return {
            "id": self.id,
            "president_email": self.president_email,
            "council_name": self.council_name,
            "ville": self.ville,
            "active": self.active,
            "created_at": self.created_at,
        }

class AdminPublique(db.Model):
    __tablename__ = "AdminPublique"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    directeur = db.Column(db.String(200), nullable=False)
    profile_image = db.Column(db.String(250))
    UserId = db.Column(db.Integer, db.ForeignKey("Users.id"))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    users = db.relationship('Users', back_populates='admin_publique')
    programmes_visite = db.relationship('ProgrammeAdmin', back_populates='admin')

    def serialize(self):
        return {
            'id': self.id,
            'firstName': self.firstName,
            'lastName': self.lastName,
            'email': self.email,
            'directeur': self.directeur,
            'profile_image': self.profile_image,
            'created_at': self.created_at
        }


class ConseillerLocal(db.Model):
    __tablename__ = "ConseillerLocal"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    profile_image = db.Column(db.String(250))  
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    programmes_visite = db.relationship('ProgrammeConseiller', back_populates='conseiller')
    resultats = db.relationship('Resultat', back_populates='conseiller')
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    users = db.relationship('Users', back_populates='conseiller_local')

    def serialize(self):
        return {
            'id': self.id,
            'firstName': self.firstName,
            'lastName': self.lastName,
            'email': self.email,
            'profile_image': self.profile_image,  
            'created_at': self.created_at
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
    conseillers = db.relationship('ProgrammeConseiller', back_populates='programme')
    admins = db.relationship('ProgrammeAdmin', back_populates='programme')
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
    
    
class ProgrammeAdmin(db.Model):
    __tablename__ = 'ProgrammeAdmin'
    programme_id = db.Column(db.Integer, db.ForeignKey('ProgrammeVisite.id'), primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('AdminPublique.id'), primary_key=True)
    admin = db.relationship("AdminPublique", back_populates="programmes_visite")
    programme = db.relationship("ProgrammeVisite", back_populates="admins")

def serialize(self):
    return {
        'programme_id': self.programme_id,
        'admin_id': self.admin_id        
    }

class ProgrammeConseiller(db.Model):
    __tablename__ = 'ProgrammeConseiller'
    programme_id = db.Column(db.Integer, db.ForeignKey('ProgrammeVisite.id'), primary_key=True)
    conseiller_id = db.Column(db.Integer, db.ForeignKey('ConseillerLocal.id'), primary_key=True)
    conseiller = db.relationship("ConseillerLocal", back_populates="programmes_visite")
    programme = db.relationship("ProgrammeVisite", back_populates="conseillers")
    
    
    
    def serialize(self):
        return {
            'programme_id': self.programme_id,
            'conseiller_id': self.conseiller_id
            # Ajoutez d'autres champs si nécessaire
        }
        
        
        
        
class Resultat(db.Model):
    __tablename__ = 'Resultat'
    id = db.Column(db.Integer, primary_key=True)
    observations = db.Column(db.Text, nullable=False)
    evaluations = db.Column(db.Text, nullable=False)
    recommendations = db.Column(db.Text, nullable=False)
    conseiller_id = db.Column(db.Integer, db.ForeignKey('ConseillerLocal.id'))
    programme_id = db.Column(db.Integer, db.ForeignKey('ProgrammeVisite.id'))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    conseiller = db.relationship("ConseillerLocal", back_populates="resultats")
    programme = db.relationship("ProgrammeVisite", back_populates="resultats")
    
    
    def serialize(self):
        return {
            'id': self.id,
            'observations': self.observations,
            'evaluations': self.evaluations,
            'recommendations': self.recommendations,
            'conseiller_id': self.conseiller_id,
            'programme_id': self.programme_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
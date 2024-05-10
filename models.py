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
    profile_image = db.Column(db.String(250))
    role_id = db.Column(db.Integer, db.ForeignKey("Role.id"))
    role = db.relationship('Role', back_populates='users')
    programmes_visite = db.relationship('ProgrammeVisite', back_populates='user', cascade='all, delete-orphan')
    phoneNumber = db.Column(db.String(20), nullable=True) 
    address = db.Column(db.String(255), nullable=True)
    

    def __repr__(self):
        return f'<User {self.firstName} {self.id}>'
    
    
    @staticmethod
    def get_user_email_by_name(nom, prenom):
        user = Users.query.filter_by(firstName=nom, lastName=prenom).first()
        if user:
            return user.email
        else:
            return None

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
            "phoneNumber": self.phoneNumber,
            "address": self.address
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
    conseiller_email = db.Column(db.String(100), nullable=False)  
    admin_email = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    user = db.relationship('Users', back_populates='programmes_visite')
    resultat = db.relationship('Resultat', back_populates='programme', uselist=False)  # Nouvelle relation
    
    
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
        
        
    @staticmethod
    def get_programmes_by_conseiller(nom, prenom):
        user = Users.query.filter_by(firstName=nom, lastName=prenom).first()
        if user:
            return ProgrammeVisite.query.filter_by(user_id=user.id).all()
        else:
            return []
    
    
        
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

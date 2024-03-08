from functools import wraps

from sqlalchemy.sql import func
from . import app,db
from flask import jsonify, request,make_response
from.models import Users,Funds
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from datetime import datetime,timedelta
from flask import jsonify


@app.route("/signup",methods=["POST"])
def signup():
    data = request.json
    email=data.get("email")
    firstName=data.get("firstName")
    lastName=data.get("lastName")
    password=data.get("password")

    if firstName and lastName and email and password:
        user = Users.query.filter_by(email=email).first()
        if user:
            return make_response(
                {
                    "message":"please Sign In"},200       
            )
        user =Users(
            email=email,
            password=generate_password_hash(password),
            firstName=firstName,
            lastName=lastName
        )
        db.session.add(user)
        db.session.commit()
        return make_response(
            {"message":"User Created"},201
        )
    return make_response(
        {"message":"Unable to create User"},500
    )

@app.route("/login",methods=["POST"])
def login():
    auth=request.json
    if not auth or not auth.get("email") or not auth.get("password"):
        return make_response(
            {"Proper Credniatials were not proviced",401}
        )
    user = Users.query.filter_by(email=auth.get("email")).first()
    if not user:
        return make_response(
            {"Please create an account ",401}
        ) 
    if check_password_hash(user.password,auth.get('password')):
        token = jwt.encode({
            'id':user.id,
            'exp':datetime.utcnow() + timedelta(minutes=30)
        },
        "secret",
        "HS256"

        )
        print("Token généré :", token)
        return make_response({'token':token},201)
    return make_response(
        {'Please check your credniatials',401}
    )

def token_required(f):

    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'Authorization' in request.headers:
            token = request.headers["Authorization"]
        if not token:
            return make_response({"message":"Token is missing "},401)
        
        try:
            data=jwt.decode(token,"secret",algorithms=["HS256"])
            current_user = Users.query.filter_by(id=data["id"]).first()
            print(current_user)
        except Exception as e :
            print(e)
            return make_response({
            "message":"token is invalid"},401)
        return f(current_user, *args,**kwargs)
    return decorated


@app.route("/funds", methods=["GET"])
@token_required
def getAllFunds(current_user):
    funds = Funds.query.filter_by(userId=current_user.id).all()
    totalSum = 0
    if funds:
        totalSum = Funds.query.with_entities(db.func.round(func.sum(Funds.amount), 2)).filter_by(userId=current_user.id).first()[0]
    return jsonify({
        "data": [fund.serialize for fund in funds],
        "sum": totalSum
    })

@app.route("/funds", methods=["POST"])
@token_required
def createFund(current_user):
    data = request.json
    amount = data.get("amount")

    if amount is not None:  # Assurez-vous que le montant n'est pas nul
        fund = Funds(
            amount=amount,
            userId=current_user.id
        )

        db.session.add(fund)
        db.session.commit()

        return make_response({"message": "Fonds créé avec succès", "fund": fund.serialize}, 201)
    else:
        return make_response({"message": "Montant invalide"}, 400)


@app.route("/funds/<id>",methods=["PUT"])
@token_required
def updateFund(current_user,id):
    try:
        funds =Funds.query.filter_by(userId=current_user.id,id=id).first()
        if funds == None:
            return make_response({"message":"unable to update"},409)
    
        data=request.json
        amount=data.get("amount")
        if amount:
            funds.amount =amount
        db.session.commit()
        return make_response({"message": funds.serialize},200) 
    except Exception as e:
        print(e)
        return make_response({"message":"Unable to process"},409)


@app.route("/funds/<id>",methods=["DELETE"])
@token_required
def deleteFund(current_user,id):
   try:
        fund =Funds.query.filter_by(userId=current_user.id,id=id).first()
        if fund == None:
            return make_response({"message":f"Fund with {id} not found"},404)
        db.session.delete(fund)
        db.session.commit()
        return make_response({"message": "Deleted"},202) 
   except Exception as e:
        print(e)
        return make_response({"message":"Unable to process"},409)

@app.route("/users", methods=["GET"])
def get_all_users():
    try:
        # Fetch all users
        users = Users.query.all()

        # Print debug information
        print("All Users:", users)

        # Commit the transaction explicitly
        db.session.commit()

        # Serialize user data
        serialized_users = [user.serialize() for user in users]  # Call the serialize method

        return jsonify({"data": serialized_users}), 200

    except Exception as e:
        print(e)
        # Rollback the transaction in case of an exception
        db.session.rollback()
        return make_response({"message": f"Error: {str(e)}"}, 500)


# ...

@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            return make_response({"message": f"User with id {user_id} not found"}, 404)

        data = request.json
        user.firstName = data.get("firstName", user.firstName)
        user.lastName = data.get("lastName", user.lastName)
        user.email = data.get("email", user.email)

        db.session.commit()

        return make_response({"message": "User updated successfully", "user": user.serialize()}, 200)

    except Exception as e:
        print(e)
        db.session.rollback()
        return make_response({"message": "Unable to update user"}, 500)

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
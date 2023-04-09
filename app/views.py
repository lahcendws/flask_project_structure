import os
import datetime
from sqlalchemy.orm.exc import NoResultFound
from flask import Blueprint, jsonify, request, abort, session
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from sqlalchemy.exc import IntegrityError
import jwt
from database.database import db
# from main import jwt

from .models import Utilisateur, Tablet

auth_blueprint = Blueprint('auth', __name__)


def auth_required(func):
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.getenv('API_KEY'):
            return abort(401)
        return func(*args, **kwargs)

    return decorated


@auth_blueprint.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    data = request.get_json()
    role = data['role']
    if not username or not password:
        return jsonify({'message': 'Veuillez entrer un nom d\'utilisateur et un mot de passe.'}), 400

    if Utilisateur.query.filter_by(username=username).first():
        return jsonify({'message': 'Ce nom d\'utilisateur est déjà pris.'}), 400

    user = Utilisateur(username=username, password=password, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Vous vous êtes inscrit avec succès.'}), 201


@auth_blueprint.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Veuillez entrer un nom d\'utilisateur et un mot de passe.'}), 400

    user = Utilisateur.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Nom d\'utilisateur ou mot de passe incorrect.'}), 401

    access_token = create_access_token(identity={'id': user.id, 'role': user.role},
                                       expires_delta=datetime.timedelta(hours=1))
    return jsonify({'access_token': access_token}), 200


@auth_blueprint.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Utilisateur déconnecté'})


@auth_blueprint.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_role = get_jwt_identity()['role']
    if current_user_role != 'admin':
        return {'message': 'Only admin can delete users'}, 401
    user = Utilisateur.query.filter_by(id=user_id).first()
    if not user:
        return {'message': 'User not found'}, 404
    db.session.delete(user)
    db.session.commit()
    return {'message': 'User deleted successfully'}


@auth_blueprint.route('/users/<int:user_id>/role', methods=['PUT'])
@jwt_required()
def update_user_role(user_id):
    current_user_role = get_jwt_identity()['role']
    if current_user_role != 'admin':
        return {'message': 'Only admin can update user role'}, 401
    user = Utilisateur.query.filter_by(id=user_id).first()
    if not user:
        return {'message': 'User not found'}, 404
    data = request.get_json()
    role = data['role']
    user.role = role
    db.session.commit()
    return {'message': 'User role updated successfully'}


@auth_blueprint.route('/protected')
@jwt_required()
def protected_route():
    current_user_id = get_jwt_identity()['id']
    current_user_role = get_jwt_identity()['role']
    if current_user_role == 'admin':
        return {'message': 'Hello admin!'}
    else:
        return {'message': 'Hello user!'}


# list all tablets
@auth_blueprint.route('/tablettes', methods=['GET'])
def get_tablettes():
    tablettes = Tablet.query.all()
    return jsonify([t.to_dict() for t in tablettes])


# add tablet
@auth_blueprint.route('/tablets', methods=['POST'])
@jwt_required()
def create_tablet():
    # Récupérer le token d'authentification de l'en-tête de la requête
    # auth_header = request.headers.get('Authorization')
    # token = auth_header.split(' ')[1]
    # Décoder le token pour récupérer l'payload (y compris l'user_id)
    # payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])

    tablet_data = request.json
    code = tablet_data['code']
    sn = tablet_data['sn']
    teamviewerid = tablet_data['teamviewerid']
    shopid = tablet_data['shopid']
    idbrand = tablet_data['idbrand']
    shopname = tablet_data['shopname']
    comment = tablet_data['comment']
    emailaccount = tablet_data['emailaccount']
    user_id = get_jwt_identity()

    tablet = Tablet(code=code, sn=sn, teamviewerid=teamviewerid, shopid=shopid, idbrand=idbrand, shopname=shopname,
                    comment=comment, emailaccount=emailaccount, user_id=user_id)
    db.session.add(tablet)
    db.session.commit()

    return jsonify({"success": True, "response": "Tablet added"})


# delete tablet
@auth_blueprint.route('/tablettes/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_tablette(id):
    try:
        tablette = Tablet.query.filter_by(id=id).one()
        db.session.delete(tablette)
        db.session.commit()
        return jsonify({'message': 'Tablette supprimée avec succès'})
    except NoResultFound:
        return jsonify({'error': 'Tablette non trouvée'}), 404


# search tablet by id
@auth_blueprint.route('/tablet/<int:id>', methods=['GET'])
def trouver_tablette_par_id(id):
    try:
        tablette = Tablet.query.get(id)
        if tablette is None:
            raise Exception("Tablette non trouvée.")
        return jsonify(tablette.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)})


@auth_blueprint.route('/search', methods=['GET'])
def search_tablette():
    sn = request.args.get('sn')
    teamviewerid = request.args.get('teamviewerid')
    shopid = request.args.get('shopid')
    idbrand = request.args.get('idbrand')
    shopname = request.args.get('shopname')
    tablette = Tablet.query
    if sn:
        tablette = Tablet.query.filter_by(sn=sn).first()
    elif teamviewerid:
        tablette = Tablet.query.filter_by(teamviewerid=teamviewerid).first()
    elif shopid:
        tablette = Tablet.query.filter_by(shopid=shopid).first()
    elif idbrand:
        tablette = Tablet.query.filter_by(idbrand=idbrand).first()
    elif shopname:
        tablette = Tablet.query.filter_by(shopname=shopname).first()
    else:
        return jsonify({'error': 'Aucun champ fourni.'})

    if tablette:
        return jsonify(
            {'id': tablette.id, 'sn': tablette.sn, 'teamviewerid': tablette.teamviewerid, 'shopid': tablette.shopid,
             'idbrand': tablette.idbrand, 'shopname': tablette.shopname})
    else:
        return jsonify({'error': 'Aucune tablette trouvée.'})


# update tablet
@auth_blueprint.route('/tablet/<int:tablette_id>', methods=['PUT'])
@jwt_required()
def update_tablette(tablette_id):
    data = request.get_json()
    tablet = Tablet.query.get(tablette_id)
    if tablet is None:
        return jsonify({'error': 'Tablet not found.'}), 404
    tablet.code = data.get('code', tablet.code)
    tablet.sn = data.get('sn', tablet.sn)
    tablet.teamviewerid = data.get('teamviewerid', tablet.teamviewerid)
    tablet.shopid = data.get('shopid', tablet.shopid)
    tablet.idbrand = data.get('idbrand', tablet.idbrand)
    tablet.shopname = data.get('shopname', tablet.shopname)
    tablet.comment = data.get('comment', tablet.comment)
    tablet.emailaccount = data.get('emailaccount', tablet.emailaccount)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'A tablet with this name already exists.'}), 409

    return jsonify(tablet.to_dict()), 200

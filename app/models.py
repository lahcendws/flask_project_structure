from datetime import datetime
import _datetime
from time import timezone

from werkzeug.security import generate_password_hash, check_password_hash

from database.database import db


class Utilisateur(db.Model):
    __tablename__ = 'utilisateurs'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


def check_auth(username, password):
    user = Utilisateur.query.filter_by(username=username).first()
    if not user:
        return False
    return check_password_hash(user.password, password)


class Tablet(db.Model):
    __tablename__ = 'tablets'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), nullable=False, unique=True)
    sn = db.Column(db.String(50), nullable=False, unique=True)
    teamviewerid = db.Column(db.Integer, nullable=False, unique=True)
    shopid = db.Column(db.String(50), nullable=False)
    idbrand = db.Column(db.String(50), nullable=False)
    shopname = db.Column(db.String(50), nullable=False)
    comment = db.Column(db.String(550), nullable=True)
    emailaccount = db.Column(db.String(50), nullable=False)
    date_added = db.Column(db.String(20), default=datetime.now().strftime('%Y-%m-%d %H:%M'))
    user_id = db.Column(db.Integer, db.ForeignKey('utilisateurs.id'), nullable=False)
    user = db.relationship('Utilisateur', backref=db.backref('tablets', lazy=True))

    __table_args__ = (db.UniqueConstraint('idbrand', 'shopid', name='idbrand_shopid_uc'),)

    def __init__(self, code, sn, teamviewerid, shopid, idbrand, shopname, comment, emailaccount, user_id):
        self.code = code
        self.sn = sn
        self.teamviewerid = teamviewerid
        self.shopid = shopid
        self.idbrand = idbrand
        self.shopname = shopname
        self.comment = comment
        self.emailaccount = emailaccount
        self.user_id = user_id

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'sn': self.sn,
            'teamviewerid': self.teamviewerid,
            'shopid': self.shopid,
            'idbrand': self.idbrand,
            'shopname': self.shopname,
            'comment': self.comment,
            'emailaccount': self.emailaccount,
            'date_added': self.date_added,
            'user_id': self.user_id

        }

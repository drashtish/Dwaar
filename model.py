from flask_sqlalchemy import SQLAlchemy
from flask_security import current_user, Security, SQLAlchemySessionUserDatastore, auth_required, hash_password, roles_required, login_required, verify_password, login_user, UserMixin, RoleMixin

db=SQLAlchemy()


label_user = db.Table('label_user',
    db.Column('UsrID', db.Integer, db.ForeignKey('user.UserID')),
    db.Column('lllID', db.Integer, db.ForeignKey('label.labelID')))

class label(db.Model,RoleMixin):
    __tablename__ = ('label')
    labelID = db.Column(db.Integer, autoincrement = True, primary_key = True)
    labelName = db.Column(db.String, unique = True, nullable= False)
    Description = db.Column(db.String)
    
class user(db.Model,UserMixin):
    __tablename__ = ("user")
    UserID = db.Column(db.Integer, autoincrement=True, primary_key=True)
    Name = db.Column(db.String, nullable = False)
    Email = db.Column(db.String, unique= True, nullable=False)
    State = db.Column(db.String)
    Password = db.Column(db.String, nullable = False)
    active = db.Column(db.Boolean)
    fs_uniquifier = db.Column(db.String, unique = True, nullable = False)
    roles = db.relationship("label", secondary = label_user ,backref = db.backref('users'))
    status = db.Column(db.Integer, default = 0)
    

class song(db.Model):
    __tablename__ = ("song")
    ID = db.Column(db.Integer, autoincrement=True, primary_key=True)
    Name = db.Column(db.String, nullable = False)
    Singer = db.Column(db.String, db.ForeignKey('user.Name'))
    SingerID = db.Column(db.Integer, db.ForeignKey('user.UserID') )
    Genre = db.Column(db.String, nullable = False)
    Date = db.Column(db.String, nullable = False)
    Review=db.relationship("review",backref=db.backref("song"))


class review(db.Model):
    __tablename__ = ("review")
    ID = db.Column(db.Integer,autoincrement = True, primary_key=True)
    UsrID = db.Column(db.Integer,  db.ForeignKey('user.UserID') )
    SngID = db.Column(db.Integer, db.ForeignKey('song.ID'))
    SingerID = db.Column(db.Integer, db.ForeignKey('user.UserID'))
    Review = db.Column(db.Integer)


class playlist(db.Model):
    __tablename__ = "playlist"
    ID = db.Column(db.Integer, autoincrement = True, primary_key = True, )
    Name = db.Column(db.String, nullable = False)
    UserId = db.Column(db.Integer, db.ForeignKey('user.UserID'))



class playlistsong(db.Model):
    __tablename__ = "playlistsong"
    ID = db.Column(db.Integer, autoincrement = True, primary_key = True)
    pID = db.Column(db.Integer, db.ForeignKey('playlist.ID'))
    sID = db.Column(db.Integer, db.ForeignKey('song.ID'))



class album(db.Model):
    __tablename__ = "album"
    ID = db.Column(db.Integer, autoincrement= True, primary_key = True)
    Name = db.Column(db.String, nullable = False)
    SingerID = db.Column(db.Integer, db.ForeignKey(user.UserID))



class albumsong(db.Model):
    __tablename__ = "albumsong"
    ID = db.Column(db.Integer, autoincrement = True, primary_key = True)
    aID = db.Column(db.Integer, db.ForeignKey(album.ID))
    sID = db.Column(db.Integer, db.ForeignKey(song.ID))    
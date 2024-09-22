from flask import Flask
from flask import request, render_template, url_for, redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_security import current_user, Security, SQLAlchemySessionUserDatastore, auth_required, hash_password, roles_required, login_required, verify_password, login_user, UserMixin, RoleMixin
import matplotlib.pyplot as plt
import os
from model import *
from flask_restful import Api,Resource


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///projdb.sqlite3"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'QWERTYALPHA'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = 'TOOSALTYPASSWORD'
app.config['SECURITY_REGISTRABLE'] = True

api = Api(app)
db.init_app(app)
app.app_context().push()

user_datastore = SQLAlchemySessionUserDatastore(db.session,user,label)
security=Security(app, user_datastore)

@app.route("/", methods = ["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('login page.html')
    else:
        email = request.form.get("email")
        passw = request.form.get("password")

        em = user.query.filter_by(Email = email).first()
        if em != None and verify_password(passw, em.Password):
            return redirect(url_for('ud',userid = em.UserID ))
        else:
            flash('Incorrect Credentials! Try again','Loginerror')
            return redirect("/")
        

@app.route("/signup", methods = ["GET","POST"])
def signup():
    if request.method == "GET":
        return render_template('signup.html')
    else:
        try:
            name = request.form.get("name")
            email = request.form.get("email")
            state = request.form.get("state")
            passw = request.form.get('password')
            us = user_datastore.create_user(Name = name,Email=email,State=state,Password = hash_password(passw))
            db.session.commit()    
            return redirect('/')
        except:
            flash('This account is already registered. Try other account!','Signuperror')
            return redirect('/signup')

@app.route('/userdash/<userid>', methods = ["GET","POST"])
def ud(userid):
    useri = current_user
    if request.method == "GET":
        sng = song.query.all()
        albm = album.query.all()
        return render_template("UD.html" , userid = userid, li = sng,albm= albm)
    srch = request.form.get('whattosearch')
    if srch == (' ' or '  '):
        srch = True
    return redirect(url_for('searchbyuser',find = srch, userid = userid))


def perform_query(model, column, data):
    return db.session.query(model).filter(column.ilike(f'%{data}%')).all()


@app.route('/searchbyuser/<userid>/<find>')

def searchbyuser(find,userid):
    
    findsong = perform_query(song, song.Name, find)
    match = perform_query(user, user.Name, find)
    findsinger=[]
    for us in match:
        if any(i.labelName == 'creator' for i in us.roles):                
            findsinger.append(us)
    findgenre = perform_query(song, song.Genre, find)
    findalbum = perform_query(album, album.Name, find)
    return render_template('searchbyuser.html',userid = userid,findsong=findsong,findalbum=findalbum,findgenre=findgenre,findsinger=findsinger,find=find)


@app.route('/searchbysong/<userid>/<sgrid>')

def searchbysong(sgrid,userid):
    sgrs = song.query.filter_by(SingerID = sgrid).all()
    return render_template('searchbysong.html',sgrs=sgrs,userid=userid)


@app.route('/searchbyalbum/<userid>/<sgrid>')
def searchbyalbum(sgrid,userid):
    sgrs = album.query.filter_by(SingerID = sgrid).all()
    return render_template('searchbyalbum.html',sgrs=sgrs,userid=userid)


@app.route("/highratedsongs/<userid>")
def highratedsongs(userid):
    query = (
    db.session.query(song, db.func.avg(review.Review).label('avgrev'))
    .join(review, song.ID == review.SngID)
    .group_by(song.ID)
    .order_by(db.func.avg(review.Review).desc()).all())
    return render_template("highratedsongs.html",query = query,userid= userid)




@app.route('/creator/<userid>', methods = ["GET", "POST"])
def creator(userid):
    us = user.query.filter_by(UserID = userid).first()
    albm = album.query.filter_by(SingerID = userid)
    alist = list(albm)
    slist = list(song.query.filter_by(SingerID=userid))
    sdup = slist
    sdup.reverse()
    if us.status == 0:
        if any(i.labelName == 'creator' for i in us.roles):
            return render_template('CD.html', userid = userid, albm = albm, alist = alist, slist = slist, sdup =sdup)
        else:
            return render_template('newcrtr.html', userid = userid)
    elif us.status == 1:
        flash('Your access to be a creator has been denied by admin. ', 'black')
        return redirect(url_for('ud',userid = userid))


@app.route('/newcreator/<userid>', methods = ["GET","POST"])
def newcreator(userid):
    us = user.query.filter_by(UserID = userid).first()
    quer = label.query.get(2)
    us.roles.append(quer)
    db.session.commit()
    flash('Congratulations! You are now a creator','newcreater')
    return redirect(url_for('creator', userid  = userid))



@app.route('/admin', methods = ["GET","POST"])
def admin():
    if request.method == 'GET':
        return render_template("Adminlogin.html")
    else:
        email = request.form.get("email")
        passw = request.form.get("password")

        em = user.query.filter_by(Email = email).first()
        if em != None and  verify_password(passw, em.Password) and any(i.labelName == 'admin' for i in em.roles):
            return redirect(url_for('admindash' ))
        else:
            flash('Incorrect Credentials! Try again','Accesserror')
            return redirect("/")


@app.route('/uploadsong/<userid>', methods = ["GET","POST"])
def upload(userid):
    albm = album.query.filter_by(SingerID = userid)
    usr = user.query.get(userid)
    if request.method == 'POST':
        nm = request.form.get('title')
        sngr = usr.Name
        releasedate = request.form.get('release_date')
        gnr = request.form.get('genre')
        aid = request.form.get('aname')
        if aid is  None:
            flash('Please choose a album to proceed','albnone')
            return redirect(url_for('upload',userid=userid))  #Flash message for missing info
        con = song(Name = nm, Singer = sngr, Date = releasedate, Genre = gnr, SingerID = userid)
        db.session.add(con)
        db.session.commit()
        obc = albumsong(sID = con.ID, aID = aid )
        db.session.add(obc)
        db.session.commit()
        songs = request.files.get('file')
        songs.save('./static/'+str(con.ID)+'.mp3')
        flash('Congratulations! Your song can now by viewed by all users','uploadsong')
        return redirect(url_for('creator',userid = userid))
    return render_template('uploadsong.html',userid = userid, albm = albm)


@app.route("/songplay/<id>/<userid>", methods = ["GET","POST"])
def songplay(id,userid):
    s = song.query.get(id)
    rvw = review.query.filter_by(UsrID = userid, SngID = id).first()
    rv = review.query.filter_by(SngID = id)
    return render_template('play.html',sng = s, userid = userid, rvw = rvw,rv = rv)


@app.route('/allsongs/<userid>', methods = ["GET","POST"])
def allsongs(userid):
    us = user.query.filter_by(UserID = userid).first()
    sng = song.query.all()
    return render_template("allsongs.html", sng = sng, userid=userid)


@app.route("/genre/<genr>/<userid>", methods = ["GET", "POST"])
def genre(genr,userid):
    sng = song.query.all()
    return render_template('genre.html', sng = sng, gen = genr, userid=userid)


@app.route("/viewgenre/<userid>", methods =["GET", "POST"])
def viewgenre(userid):
    sng = song.query.all()
    return render_template('viewgenre.html', sng = sng,userid=userid)

@app.route('/review/<snID>/<snSingerID>/<userid>', methods = ["GET","POST"])
def revw(snID, snSingerID,userid):
    us = user.query.filter_by(UserID = userid).first()
    sng = song.query.get(snID)
    rvw = review.query.filter_by(UsrID = us.UserID, SngID = snID).first()
    if request.method == "GET":
        if rvw is not None:
           return render_template('review.html', sng = sng , userid = userid,  rvw = rvw)
        return render_template('review.html', sng = sng , userid = userid, rvw = rvw)
    else:
        if rvw is not None:
            newrev = request.form.get('review')
            rvw.Review = newrev
            db.session.commit()
            return redirect(url_for('songplay', id = snID, userid=userid))
        UsrID = us.UserID
        SingerID = snSingerID
        SngID = snID
        r = request.form.get('review')
        ad = review(UsrID = UsrID, SingerID=SingerID, SngID = SngID, Review =r )
        db.session.add(ad)
        db.session.commit()
        return redirect(url_for('songplay', id = snID, userid=userid))


@app.route('/profile/<userid>', methods = ["GET", "POST"])
def profile(userid):
    usr = user.query.get(userid)
    p = playlist.query.filter_by(UserId = userid)
    return render_template('profile.html', pl = p, userid = userid,usr=usr)


@app.route('/allplaylist/<userid>')
def allplaylist(userid):
    p = playlist.query.filter_by(UserId = userid).all()
    return render_template('allplaylist.html', p = p, userid = userid)


@app.route("/playlist/<userid>/<pid>")
def playlis(userid,pid):
    p = playlistsong.query.filter_by(pID = pid)
    sngid = []
    for i in p:
        sngid.append(i.sID)
    slist = []
    for i in sngid:
        obj = song.query.filter_by(ID = i).first()
        slist.append(obj)
    pllt = playlist.query.get(pid)
    return render_template('songplaylist.html', s=slist, userid=userid,pid = pid,pllt=pllt)


@app.route('/createplaylist/<userid>', methods = ['GET','POST'])
def createpl(userid):
    if request.method == "GET":
        return render_template("createplaylist.html", userid = userid)
    nm = request.form.get('playlistname')
    pl = playlist.query.filter_by(Name = nm, UserId = userid).first()
    if pl is not None:
        flash('Please enter a different name for playlist','plnameerror')
        return redirect(url_for('createpl',userid = userid))        
    p = playlist(Name = nm, UserId = userid)
    db.session.add(p)
    db.session.commit()
    return redirect(url_for('allplaylist', userid = userid))


@app.route('/songsnewplaylist/<userid>/<sid>', methods = ['GET','POST'])
def songsnewplaylist(userid,sid):
    if request.method == "GET":
        return render_template("songsnewplaylist.html", userid = userid, sid = sid)
    nm = request.form.get('playlistname')
    pl = playlist.query.filter_by(Name = nm, UserId = userid).first()
    if pl is not None:
        flash('Please enter a different name for playlist','plnameerror')
        return redirect(url_for('songsnewplaylist',userid = userid,sid =sid))        
    p = playlist(Name = nm, UserId = userid)
    db.session.add(p)
    db.session.commit()
    return redirect(url_for('songtoplaylist', userid = userid,sid = sid))


@app.route('/songtoplaylist/<userid>/<sid>', methods = ['GET','POST'])
def songtoplaylist(userid,sid):
    pl = playlist.query.filter_by(UserId = userid)
    if request.method == "GET":
        return render_template('addstop.html', pl = pl, userid = userid, sid = sid)
    name = request.form.get('pname')   
    psong = playlistsong.query.filter_by(pID = name, sID = sid).first()
    if psong is not None:
        flash('Please select a different playlist name to proceed')
        return redirect(url_for('songtoplaylist', userid = userid,sid=sid)) 
    obj = playlistsong(pID = name,sID = sid )
    db.session.add(obj)
    db.session.commit()
    flash('Your song is added to your desired playlist','stop')
    return redirect(url_for('songplay',userid =userid, id = sid))



@app.route('/editplaylist/<userid>/<pid>',methods = ['GET','POST'])
def editplaylist(userid,pid):
    p = playlist.query.get(pid)
    if request.method == 'GET':
        return render_template('editplaylist.html',userid=userid,pid=pid,p=p)
    pname = request.form.get('playlistname')
    sm = playlist.query.filter_by(Name = pname, UserId = userid).first()
    if sm is None:
        p.Name = pname
        db.session.commit()
        flash('Playlist Name has been updated')
        return redirect(url_for('playlis',userid=userid,pid=pid))
    flash('Enter different name to proceed')
    return redirect(url_for('editplaylist',userid=userid,pid=pid))



@app.route('/removefrompl/<userid>/<sid>/<pid>',methods = ['GET','POST'])
def removefrompl(userid,sid,pid):
    r = playlistsong.query.filter_by(pID = pid,sID = sid).first()
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for('playlis',userid=userid,pid=pid))


@app.route('/removepl/<userid>/<pid>', methods = ['GET','POST'])
def removepl(userid,pid):
    pl = playlist.query.filter_by(ID = pid).first()
    db.session.query(playlistsong).filter_by(pID=pid).delete()
    db.session.delete(pl)
    db.session.commit()
    return redirect(url_for('allplaylist', userid = userid))


@app.route('/allalbum/<cid>',methods = ['GET','POST'])
def allalbum(cid):
    a = album.query.filter_by(SingerID = cid).all()
    return render_template('allalbum.html', al = a , cid = cid)


@app.route('/albm/<cid>/<aid>', methods = ['GET','POST'])
def albm(cid, aid):
    a = albumsong.query.filter_by(aID = aid)
    sngid = []
    for i in a:
        sngid.append(i.sID)
    slist = []
    for i in sngid:
        obj = song.query.filter_by(ID = i).first()
        slist.append(obj)
    albm = album.query.get(aid)
    return render_template('albm.html', s = slist, cid = cid,aid = aid,albm = albm)


@app.route('/editalbum/<cid>/<aid>',methods = ['GET','POST'])
def editalbum(cid,aid):
    a = album.query.get(aid)
    if request.method == 'GET':
        return render_template('editalbum.html',cid=cid,aid=aid,a=a)
    aname = request.form.get('albumname')
    sm = album.query.filter_by(Name = aname, SingerID= cid).first()
    if sm is None:
        a.Name = aname
        db.session.commit()
        flash('Album Name has been updated')
        return redirect(url_for('albm',cid=cid,aid=aid))
    flash('Enter different name to proceed')
    return redirect(url_for('editalbum',cid=cid,aid=aid))



@app.route('/createalbum/<cid>', methods = ['GET','POST'])
def createalbum(cid):
    if request.method == "GET":
        return render_template("createalbum.html", cid = cid)
    nm = request.form.get('albumname')
    a = album.query.filter_by(Name = nm, SingerID = cid).first()
    if a is not None:
        flash('Please enter a different album name to proceed','duperror')
        return redirect(url_for('createalbum',cid = cid))        
    obj = album(Name = nm, SingerID= cid)
    db.session.add(obj)
    db.session.commit()
    return redirect(url_for('allalbum', cid = cid))


@app.route('/newalbum/<cid>', methods = ['GET','POST'])
def newalbum(cid):
    if request.method == 'GET':
        return render_template('newalbum.html',cid = cid)
    nm = request.form.get('albumname')
    a = album.query.filter_by(Name = nm, SingerID = cid).first()
    if a is not None:
        flash('Please enter a different album name to proceed','duperror')
        return redirect(url_for('newalbum',cid = cid))        
    obj = album(Name = nm, SingerID= cid)
    db.session.add(obj)
    db.session.commit()
    return redirect(url_for('upload', userid = cid))



@app.route('/changesongnewalbum/<cid>/<sid>', methods = ['GET','POST'])
def changesongnewalbum(cid,sid):
    if request.method == 'GET':
        return render_template('changesongnewalbum.html',cid = cid,sid=sid)
    nm = request.form.get('albumname')
    a = album.query.filter_by(Name = nm, SingerID = cid).first()
    if a is not None:
        flash('Please enter a different album name to proceed','duperror')
        return redirect(url_for('changesongnewalbum',cid = cid,sid = sid))        
    obj = album(Name = nm, SingerID= cid)
    db.session.add(obj)
    db.session.commit()
    return redirect(url_for('songtoalbum', cid = cid,sid=sid))


    

@app.route('/removefromal/<cid>/<sid>/<aid>',methods = ['GET','POST'])
def removefromal(cid,sid,aid):
    r = albumsong.query.filter_by(aID = aid,sID = sid).first()
    db.session.delete(r)
    db.session.commit()
    return redirect(url_for('albm',cid=cid,aid=aid))


@app.route('/deletealbum/<cid>/<aid>', methods = ['GET','POST'])
def deletealbum(cid,aid):
    db.session.query(album).filter_by(ID = aid).delete()
    db.session.query(albumsong).filter_by(aID = aid).delete()
    db.session.commit()
    return redirect(url_for('allalbum',cid = cid))



@app.route('/creatorsongs/<cid>', methods = ['GET','POST'])
def creatorsongs(cid):
    a = song.query.filter_by(SingerID = cid).all()
    return render_template('creatorsongs.html', a= a, cid = cid)


@app.route('/removesong/<cid>/<sid>',methods =['GET','POST'])
def removesong(cid,sid):
    db.session.query(song).filter_by(ID=sid).delete()
    db.session.query(playlistsong).filter_by(sID=sid).delete()
    db.session.query(albumsong).filter_by(sID=sid).delete()
    db.session.query(review).filter_by(SngID=sid).delete()
    os.remove('./static/'+str(sid)+'.mp3')
    db.session.commit()
    return redirect(url_for('creatorsongs',cid = cid))


@app.route('/updatesong/<cid>/<sid>', methods = ['GET','POST'])
def updatesong(cid,sid):
    s = song.query.get(sid)
    albm = album.query.filter_by(SingerID = cid)
    asng = albumsong.query.filter_by(sID = sid).first()
    if request.method=='GET':
        return render_template('updatesong.html',s = s, cid = cid,albm=albm, sng = asng)
    nm = request.form.get('title')
    an = request.form.get('aname')
    gn = request.form.get('genre')
    songs = request.files.get('file')
    if songs.filename  != '':
        songs.save('./static/'+str(s.ID)+'.mp3')
    s.Name,s.Genre = nm,gn
    if asng is not None:
        asng.aID = an
    else:
        data = albumsong(aID = an,sID = sid )
        db.session.add(data)
    db.session.commit()
    flash('Song details has been updated successfully','updsng')
    return redirect(url_for('creatorsongs',cid = cid))


@app.route('/creatorsplay/<sid>/<cid>',methods=['GET','POST'])
def creatorsplay(sid,cid):
    s = song.query.filter_by(ID = sid).first()
    rvw = review.query.filter_by(SingerID = cid,SngID=sid)
    return render_template('creatorsplay.html',sng = s, cid = cid , rvw = rvw)


@app.route('/songtoalbum/<cid>/<sid>', methods = ['GET','POST'])
def songtoalbum(cid,sid):
    albm = album.query.filter_by(SingerID=cid)
    asng= albumsong.query.filter_by(sID=sid).first()
    if request.method =='GET':
        return render_template('songtoalbum.html',sid = sid,cid=cid,albm = albm, sng=asng)
    aname = request.form.get('aname')
    asong = albumsong.query.filter_by(sID = sid).first()
    if asong is None:
        rec = albumsong(sID = sid, aID = aname)
        db.session.add(rec)
        db.session.commit()
        flash('This song has been added to your desired album','updatealbum')
        return redirect(url_for('creatorsplay',cid = cid,sid=sid)) 
    asng.aID = aname
    db.session.commit()
    flash('This song has been added to your desired album','updatealbum')
    return redirect(url_for('creatorsplay',sid = sid, cid = cid))



@app.route('/useralbum/<userid>',methods =['GET','POST'])
def useralbum(userid):
    albm = album.query.all()
    return render_template('useralbum.html',albm=albm, userid=userid)


@app.route('/useralbumsong/<userid>/<aid>', methods = ['GET','POST'])
def useralbumsong(userid,aid):
    a = albumsong.query.filter_by(aID = aid)
    sngid = []
    for i in a:
        sngid.append(i.sID)
    slist = []
    for i in sngid:
        obj = song.query.filter_by(ID = i).first()
        slist.append(obj)
    albm = album.query.get(aid)
    return render_template('useralbumsong.html', s = slist,userid=userid,albm =albm)


plt.switch_backend('agg')

@app.route('/admindash', methods=['GET','POST'])
def admindash():
    if request.method == 'GET':
        u = list(user.query.all())
        s = list(song.query.all())
        a = list(album.query.all())
        c = []
        for us in u:
            if any(i.labelName == 'creator' for i in us.roles):                
                c.append(us)
        song_reviews_data = db.session.query(song.Name, db.func.avg(review.Review)).\
        outerjoin(review, song.ID == review.SngID).group_by(song.ID).all()

        #if not song_reviews_data:
        #    return "No data available for the singer histogram."
        if song_reviews_data:
            song_titles, average_ratings = zip(*song_reviews_data)

            fig, ax = plt.subplots()
            ax.plot(song_titles, average_ratings, marker='o', color='green', linestyle='-', linewidth=2)
            ax.set_xlabel('Songs')
            ax.set_ylabel('Average Ratings')
            ax.set_title('Line Graph for Song and Average Ratings')

            ax.set_xticklabels(song_titles, rotation=5, ha='right')
            ax.set_ylim(0, 5)

            scat = "static/scatter.png"
            fig.savefig(scat)
            plt.close(fig)
        return render_template('AD.html', u=u, s=s, a=a, c= c,gh = song_reviews_data)
    if request.method == 'POST':
        find = request.form.get('whattosearch')
        if find == (' ' or '  '):
            find = True
        return redirect(url_for('searchbyadmin',find = find))



@app.route('/searchbyadmin/<find>')
def searchbyadmin(find):
        usr = user.query.all()
        sng = song.query.all()
        albm = album.query.all()
        findsong = perform_query(song, song.Name, find)
        match = perform_query(user, user.Name, find)
        findsinger=[]
        for us in match:
            if any(i.labelName == 'creator' for i in us.roles):                
                findsinger.append(us)
        findgenre = perform_query(song, song.Genre, find)
        findalbum = perform_query(album, album.Name, find)
        return render_template('searchbyadmin.html',sng = sng,albm=albm,find = find,
        usr=usr,findsong=findsong,findalbum=findalbum,findgenre=findgenre,findsinger=findsinger)



@app.route('/adminsearchstatus/<userid>/<status>/<find>')
def adminsearchstatus(userid,status,find):
    stat = user.query.get(userid)
    stat.status = status
    db.session.commit()
    return redirect(url_for('searchbyadmin',find=find))



@app.route('/adminfindsong/<cid>')
def adminfindsong(cid):
    sgrs = song.query.filter_by(SingerID = cid).all()
    print(sgrs)
    return render_template('adminfindsong.html',sgrs=sgrs)


@app.route('/adminfindalbum/<cid>')
def adminfindalbum(cid):
    singers = album.query.filter_by(SingerID=cid).all()
    print(singers)
    return render_template('adminfindalbum.html',sgrs=singers)




@app.route('/adminfinddltsong/<sid>/<cid>')
def adminfinddltsong(sid,cid):
    db.session.query(song).filter_by(ID=sid).delete()
    db.session.query(playlistsong).filter_by(sID=sid).delete()
    db.session.query(albumsong).filter_by(sID=sid).delete()
    db.session.query(review).filter_by(SngID=sid).delete()
    os.remove('./static/'+str(sid)+'.mp3')
    db.session.commit()
    return redirect(url_for('adminfindsong',cid = cid))


@app.route('/adminfindbardltsong/<sid>/<cid>/<find>')
def adminfindbardltsong(sid,cid,find):
    db.session.query(song).filter_by(ID=sid).delete()
    db.session.query(playlistsong).filter_by(sID=sid).delete()
    db.session.query(albumsong).filter_by(sID=sid).delete()
    db.session.query(review).filter_by(SngID=sid).delete()
    os.remove('./static/'+str(sid)+'.mp3')
    db.session.commit()
    return redirect(url_for('searchbyadmin',find= find))




@app.route('/adminfinddltalbum/<aid>')
def adminfinddltalbum(aid):
    a = album.query.get(aid)
    cid = a.SingerID
    db.session.query(album).filter_by(ID = aid).delete()
    db.session.query(albumsong).filter_by(aID = aid).delete()
    db.session.commit()
    return redirect(url_for('adminfindalbum',cid = cid))


@app.route('/adminfindbardltalbum/<aid>/<find>')
def adminfindbardltalbum(aid,find):
    db.session.query(album).filter_by(ID = aid).delete()
    db.session.query(albumsong).filter_by(aID = aid).delete()
    db.session.commit()
    return redirect(url_for('searchbyadmin',find=find))






@app.route('/adminsongplay/<sid>',methods = ['GET','POST'])
def adminplay(sid):
    if request.method == 'GET':
        s = song.query.get(sid)
        rvw = review.query.filter_by(SngID=sid)
        return render_template('adminsongplay.html',sng= s,rvw = rvw)


@app.route('/adminallsongs', methods = ['GET','POST'])
def adminallsongs():
    if request.method == 'GET':
        s = song.query.all()
        return render_template('adminallsongs.html',s = s)


@app.route('/deletesongbyadmin/<sid>')
def deletesongbyadmin(sid):
    if request.method == 'GET':
        db.session.query(song).filter_by(ID=sid).delete()
        db.session.query(playlistsong).filter_by(sID=sid).delete()
        db.session.query(albumsong).filter_by(sID=sid).delete()
        db.session.query(review).filter_by(SngID=sid).delete()
        os.remove('./static/'+str(sid)+'.mp3')
        db.session.commit()
        return redirect(url_for('adminallsongs'))


@app.route('/adminallalbums', methods = ['GET','POST'])
def adminallalbums():
    if request.method == 'GET':
        sng = song.query.all()
        albm = album.query.all()
        return render_template('adminallalbums.html',albm = albm,sng = sng)
    

@app.route('/adminsongofalbum/<aid>')
def adminsongofalbum(aid):
    a = albumsong.query.filter_by(aID = aid)
    sngid = []
    for i in a:
        sngid.append(i.sID)
    slist = []
    for i in sngid:
        obj = song.query.filter_by(ID = i).first()
        slist.append(obj)
    albm = album.query.get(aid)
    return render_template('adminsongofalbum.html', s = slist,albm = albm)



@app.route('/deletealbumbyadmin/<aid>')
def deletealbumbyadmin(aid):
    db.session.query(album).filter_by(ID = aid).delete()
    db.session.query(albumsong).filter_by(aID = aid).delete()
    db.session.commit()
    return redirect(url_for('adminallalbums'))


@app.route('/adminallgenre')
def adminallgenre():
    sng = song.query.all()
    return render_template('adminallgenre.html', sng = sng)


@app.route("/admingenre/<genr>", methods = ["GET", "POST"])
def admingenre(genr):
    sng = song.query.all()
    return render_template('admingenre.html', sng = sng, gen = genr)


@app.route('/adminallcreators')
def adminallcreators():
    u = list(user.query.all())
    c = []
    for us in u:
        if any(i.labelName == 'creator' for i in us.roles):                
            c.append(us)
    sng = song.query.all()
    albm = album.query.all()
    rvw = review.query.all()
    singers_data = db.session.query(user.Name, db.func.avg(review.Review)).\
    join(song, song.SingerID == user.UserID).join(review,song.ID == review.SngID).\
    group_by(user.UserID).all()

    if singers_data:
        
        singer_names, avg_reviews = zip(*singers_data)


        fig, ax = plt.subplots()
        ax.bar(singer_names, avg_reviews, color='orange', width=0.2)
        ax.set_xlabel('Singer Name')
        ax.set_ylabel('Average Reviews')
        ax.set_title('Histogram of Singers and Average Reviews')
        ax.set_ylim(0,5)

        hist = "static/histogram.png"
        fig.savefig(hist)
        plt.close(fig)  

    return render_template('adminallcreators.html', c = c, sng = sng,albm = albm,rvw =rvw,s = singers_data)
    

@app.route('/adminchangestatus/<cid>/<status>')
def adminchangestatus(cid,status):
    stat = user.query.get(cid)
    stat.status = status
    db.session.commit()
    return redirect('/adminallcreators')



@app.route('/logout/<userid>')
def logout(userid):
    return redirect('/')

class ApiforSong(Resource):
    def put(self):
        user_id = request.form.get('ID')
        usr = user.query.get(user_id)
        sid = request.form.get('song_id')
        albs=album.query.filter_by(SingerID=usr.UserID)
        albson=albumsong.query.filter_by(sID=sid).first()
        songobj=song.query.get(sid)
        name=request.form.get("title")
        albumi=request.form.get("aname")
        genre=request.form.get("genre")
        if albson is None:
            o=albumsong(aID=albumi,sID=sid)
            db.session.add(o)
        else:
            albson.aID=albumi
        songobj.Name=name
        songobj.Genre=genre
        f=request.files.get("file")
        if f.filename != '':
            f.save('./static/'+str(songobj.ID)+'.mp3')
        db.session.commit()
        return {'msg':'Song Updated Successfully!!!'},200
  
    def get(self):
        sid = request.get_json().get('id')
        sng = song.query.get(sid)
        if sng is None:
            return 'song not found',404
        return {
            'id':sng.ID,
            'name':sng.Name,
            'singer':sng.Singer,
            'genre':sng.Genre
        },200



    def post(self):
        user_id = request.form.get('ID')
        usr = user.query.get(user_id)
        print(usr)
        name=request.form.get("title")
        singer=usr.Name
        file=request.files.get("file")
        genre=request.form.get("genre")
        date=request.form.get("release_date")
        albmid=request.form.get("aname")
        sid=usr.UserID
        d=song(Name=name,Singer=singer,Genre=genre,Date=date,SingerID=sid)
        db.session.add(d)
        db.session.commit()
        ob=albumsong(sID=d.ID,aID=albmid)
        db.session.add(ob)
        db.session.commit()
        file.save('./static/'+str(d.ID)+'.mp3')
        return {'song_id':d.ID},200


    def delete(self):
        sid = request.get_json().get('Id')
        sng=song.query.get(sid)
        if sng is None:
            return 'song not found',404
        db.session.query(playlistsong).filter_by(sID=sid).delete()
        db.session.query(albumsong).filter_by(sID=sid).delete()
        db.session.query(review).filter_by(SngID=sid).delete()
        os.remove('./static/'+str(sid)+'.mp3')
        db.session.delete(sng)
        db.session.commit()
        return {'msg':'Song Removed Successfully!!!'},200


class ApiforPlaylist(Resource):

    def get(self):
        playlist_id = request.get_json().get('playlist_id')
        plist = playlist.query.get(playlist_id)
        if plist is None:
            return 'playlist not found',404
        return {
            'playlist_id':plist.ID,
            'playlist_name':plist.Name,
            'user_id':plist.UserId
        },200


    def post(self):
        user_id=request.get_json().get("user_id")
        name=request.get_json().get("name")
        data=playlist(Name=name,UserId=user_id)
        db.session.add(data)
        db.session.commit()
        return {'msg':'Playlist Added Succesfully!!'},200


    def put(self):
        user_id=request.get_json().get("user_id")
        playlist_id=request.get_json().get("playlist_id")
        name=request.get_json().get("name")
        plist = playlist.query.get(playlist_id)
        if plist is None:
            return 'playlist not found',404
        plist.Name = name
        plist.UserId = user_id
        db.session.commit()
        return {'msg':'Playlist Updated Succesfully!!'},200


    def delete(self):
        playlist_id=request.get_json().get("playlist_id")
        plist = playlist.query.get(playlist_id)
        if plist is None:
            return 'playlist not found',404
        db.session.query(playlistsong).filter_by(pID=playlist_id).delete()
        db.session.delete(plist)
        db.session.commit()
        return {'msg':'Playlist Removed Succesfully!!'},200



api.add_resource(ApiforSong,'/api/Song')
api.add_resource(ApiforPlaylist,'/api/Playlist')


app.run(debug=True)



import sys

from flask import Flask, escape, request, flash, redirect, url_for, render_template, jsonify, session, make_response
import os
from werkzeug.utils import secure_filename
from shutil import copyfile, rmtree
from flask_bootstrap import Bootstrap
from os import listdir
from os.path import isfile, join

from flask_login import LoginManager
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

import util

from db import db
from context import webauthn
from models import User

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField, FileField
from wtforms.validators import DataRequired, Length


from datetime import timedelta
from flask import make_response, request, current_app
from functools import update_wrapper

UPLOAD_FOLDER = 'static'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

class HelloForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(1, 20)])
    file = FileField(u'File(s)')
    submit = SubmitField()

def crossdomain(origin=None, methods=None, headers=None, max_age=21600,
                attach_to_all=True, automatic_options=True):
    """Decorator function that allows crossdomain requests.
      Courtesy of
      https://blog.skyred.fi/articles/better-crossdomain-snippet-for-flask.html
    """
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    # use str instead of basestring if using Python 3.x
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    # use str instead of basestring if using Python 3.x
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        """ Determines which methods are allowed
        """
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        """The decorator function
        """
        def wrapped_function(*args, **kwargs):
            """Caries out the actual cross domain code
            """
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers
            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            h['Access-Control-Allow-Credentials'] = 'true'
            h['Access-Control-Allow-Headers'] = \
                "Origin, X-Requested-With, Content-Type, Accept, Authorization"
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator

app = Flask(__name__, static_url_path='')
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(
    os.path.join(os.path.dirname(os.path.abspath(__name__)), 'webauthn.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug = True

bootstrap = Bootstrap(app)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

RP_ID = 'localhost'
ORIGIN = 'https://localhost:5000'

# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'


@login_manager.user_loader
def load_user(user_id):
    try:
        int(user_id)
    except ValueError:
        return None

    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/borrar', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        uploaded_files = request.files.getlist("file")
        # file = request.files['file']
        print(len(uploaded_files))
        print(request.form["name"])
        name = request.form["name"]
        if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], name)):
            os.mkdir( os.path.join(app.config['UPLOAD_FOLDER'], name), 0755 )
        f= open(app.config['UPLOAD_FOLDER']+"/"+ name + "/tmp.txt","w+")
        for i, file in enumerate(uploaded_files):
            print(str(i) + " " + file.filename)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                print(os.path.splitext(filename)[0])
                f.write("page-" + str(i + 1) + ".jpg" + "\n")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], name, "page-" + str(i + 1) + ".jpg"))
        f.close()
        os.system("cd static/" + name + "; /usr/bin/tesseract" + " tmp.txt " + name + " -l eng hocr; cd ../..;")
        cwd = os.getcwd()
        print(cwd)
        os.remove(app.config['UPLOAD_FOLDER']+"/"+ name + "/tmp.txt")
        # if user does not select file, browser also
        # submit an empty part without filename
        # if file.filename == '':
        #     flash('No selected file')
        #     return redirect(request.url)
        # if file and allowed_file(file.filename):
        #     filename = secure_filename(file.filename)
        #     print(os.path.splitext(filename)[0])
        #     if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], os.path.splitext(filename)[0])):
        #         os.mkdir( os.path.join(app.config['UPLOAD_FOLDER'], os.path.splitext(filename)[0]), 0755 );
        #     file.save(os.path.join(app.config['UPLOAD_FOLDER'], os.path.splitext(filename)[0], filename))
        #     print("/usr/bin/tesseract" + " " + os.path.join(app.config['UPLOAD_FOLDER'], filename) + " " + os.path.join(app.config['UPLOAD_FOLDER'], "0001") + " -l eng hocr")
        #     os.system("cd static/" + os.path.splitext(filename)[0] + "; /usr/bin/tesseract" + " " + filename + " " + os.path.splitext(filename)[0] + " -l eng hocr ")
            # return redirect(url_for('upload_file',
            #                         filename=filename))
        return redirect(url_for('upload_file'))
    os.chdir("static")
    docs = [name for name in os.listdir(".") if os.path.isdir(name)]
    os.chdir("..")
    return render_template('index.html', links = docs)

@app.route('/upload', methods=['POST'])
def upload():
    if request.method == 'POST':
        print(request.files)
        # file = request.files['data']
        return("It worked")
        
    # filename = secure_filename(file.filename)
    # file.save(os.path.join(app.config['upload_folder'], filename))

@app.route("/editing")
def editing():
    file = request.args.get('file', type = str)
    return render_template('edit.html',file = file)
        
# @app.route("/editing")
# def editing():
#         return render_template('edit.html')

@app.route('/save', methods=['POST'])
# @crossdomain(origin='*')
def hello():
    file = request.args.get('file', type = str)
    hocr = request.form["hocr"]
    print(file)
    cwd = os.getcwd()
    print(cwd)
    f= open("static/" + file + "/" + file + ".hocr","w")
    # if not os.path.exists("reviewed_files/"+file):
    #         os.mkdir( os.path.join("reviewed_files",file), 0755 );
    # f = open("reviewed_files/"+ file +"/"+ file +".hocr","wr+")
    f.write(hocr.encode('utf8'))
    f.close()
    print(file)
    print("cd static/" + file + "; /usr/local/bin/hocr-split "+ file +".hocr page-%01d.hocr; cd ../..;")
    os.system("cd static/" + file + "; /usr/local/bin/hocr-split "+ file +".hocr page-%01d.hocr; cd ../..;")
    # copyfile(os.path.join("static", file, file + ".jpg"), os.path.join("reviewed_files",file,file + ".jpg"))
    os.system("/usr/local/bin/hocr-pdf static/"+ file +"/ > static/files/" + file + ".pdf")
    copyfile("static/" + file + "/page-1.jpg", "static/files/" + file + ".jpg")
    rmtree("static/"+file+"/")
    return redirect(url_for('upload_file'))


@app.route('/', methods=['GET', 'POST'])
def borrar():
    form = HelloForm()
    form.file.multiple = "multiple"
    print(form.file.flags.__dict__)
    form.file(multiple="multiple")
    if request.method == 'POST':
        print(request.form)
        if 'file' not in request.files:
            print("No file part")
            flash('No file part')
            return redirect(request.url)
        uploaded_files = request.files.getlist("file")
        print(len(uploaded_files))
        print(request.form["name"])
        name = request.form["name"]
        if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], name)):
            os.mkdir( os.path.join(app.config['UPLOAD_FOLDER'], name), 0755 )
        f= open(app.config['UPLOAD_FOLDER']+"/"+ name + "/tmp.txt","w+")
        for i, file in enumerate(uploaded_files):
            print(str(i) + " " + file.filename)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                print(os.path.splitext(filename)[0])
                f.write("page-" + str(i + 1) + ".jpg" + "\n")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], name, "page-" + str(i + 1) + ".jpg"))
        f.close()
        os.system("cd static/" + name + "; /usr/bin/tesseract" + " tmp.txt " + name + " -l eng hocr; cd ../..;")
        cwd = os.getcwd()
        print(cwd)
        os.remove(app.config['UPLOAD_FOLDER']+"/"+ name + "/tmp.txt")
        return redirect(url_for('borrar'))
    os.chdir("static")
    docs = [name for name in os.listdir(".") if os.path.isdir(name) and name != "files" and name != "icons"]
    os.chdir("..")
    return render_template('borrar.html', form = form, links = docs)

@app.route('/terminados')
def terminados():

    onlyfiles = [f for f in listdir("static/files/") if isfile(join("static/files/", f)) and f.endswith(".pdf")]
    onlyfiles = map(lambda x: x[:-4], onlyfiles)

    print(onlyfiles)
    return render_template('terminados.html', files = onlyfiles)

# Authentication part

@app.route('/webauthn_begin_activate', methods=['POST'])
def webauthn_begin_activate():
    # MakeCredentialOptions
    username = request.form.get('register_username')
    display_name = request.form.get('register_display_name')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)
    if not util.validate_display_name(display_name):
        return make_response(jsonify({'fail': 'Invalid display name.'}), 401)

    if User.query.filter_by(username=username).first():
        return make_response(jsonify({'fail': 'User already exists.'}), 401)

    if 'register_ukey' in session:
        del session['register_ukey']
    if 'register_username' in session:
        del session['register_username']
    if 'register_display_name' in session:
        del session['register_display_name']
    if 'challenge' in session:
        del session['challenge']

    session['register_username'] = username
    session['register_display_name'] = display_name

    print(username, display_name)

    rp_name = 'localhost'
    challenge = util.generate_challenge(32)
    ukey = util.generate_ukey()

    session['challenge'] = challenge
    session['register_ukey'] = ukey

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, rp_name, RP_ID, ukey, username, display_name,
        'https://example.com')

    return jsonify(make_credential_options.registration_dict)


@app.route('/webauthn_begin_assertion', methods=['POST'])
def webauthn_begin_assertion():
    username = request.form.get('login_username')

    if not util.validate_username(username):
        return make_response(jsonify({'fail': 'Invalid username.'}), 401)

    user = User.query.filter_by(username=username).first()

    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)
    if not user.credential_id:
        return make_response(jsonify({'fail': 'Unknown credential ID.'}), 401)

    if 'challenge' in session:
        del session['challenge']

    challenge = util.generate_challenge(32)

    session['challenge'] = challenge

    webauthn_user = webauthn.WebAuthnUser(
        user.ukey, user.username, user.display_name, user.icon_url,
        user.credential_id, user.pub_key, user.sign_count, user.rp_id)

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user, challenge)

    return jsonify(webauthn_assertion_options.assertion_dict)


@app.route('/verify_credential_info', methods=['POST'])
def verify_credential_info():
    challenge = session['challenge']
    print(challenge)
    username = session['register_username']
    display_name = session['register_display_name']
    ukey = session['register_ukey']
    print(ukey)

    registration_response = request.form
    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    print("trust_anchor_dir: " + trust_anchor_dir)
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        print(e)
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})

    # Step 17.
    #
    # Check that the credentialId is not yet registered to any other user.
    # If registration is requested for a credential that is already registered
    # to a different user, the Relying Party SHOULD fail this registration
    # ceremony, or it MAY decide to accept the registration, e.g. while deleting
    # the older registration.
    credential_id_exists = User.query.filter_by(
        credential_id=webauthn_credential.credential_id).first()
    if credential_id_exists:
        return make_response(
            jsonify({
                'fail': 'Credential ID already exists.'
            }), 401)

    existing_user = User.query.filter_by(username=username).first()
    if not existing_user:
        if sys.version_info >= (3, 0):
            webauthn_credential.credential_id = str(
                webauthn_credential.credential_id, "utf-8")
            webauthn_credential.public_key = str(
                webauthn_credential.public_key, "utf-8")
        user = User(
            ukey=ukey,
            username=username,
            display_name=display_name,
            pub_key=webauthn_credential.public_key,
            credential_id=webauthn_credential.credential_id,
            sign_count=webauthn_credential.sign_count,
            rp_id=RP_ID,
            icon_url='https://example.com')
        db.session.add(user)
        db.session.commit()
    else:
        return make_response(jsonify({'fail': 'User already exists.'}), 401)

    flash('Successfully registered as {}.'.format(username))

    return jsonify({'success': 'User successfully registered.'})


@app.route('/verify_assertion', methods=['POST'])
def verify_assertion():
    challenge = session.get('challenge')
    assertion_response = request.form
    credential_id = assertion_response.get('id')

    user = User.query.filter_by(credential_id=credential_id).first()
    if not user:
        return make_response(jsonify({'fail': 'User does not exist.'}), 401)

    webauthn_user = webauthn.WebAuthnUser(
        user.ukey, user.username, user.display_name, user.icon_url,
        user.credential_id, user.pub_key, user.sign_count, user.rp_id)

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        uv_required=False)  # User Verification

    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

    # Update counter.
    user.sign_count = sign_count
    db.session.add(user)
    db.session.commit()

    login_user(user)

    return jsonify({
        'success':
        'Successfully authenticated as {}'.format(user.username)
    })


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('borrar'))

if __name__ == "__main__":
    app.run(ssl_context='adhoc', debug=True)

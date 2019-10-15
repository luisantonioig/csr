from flask import Flask, escape, request, flash, redirect, url_for, render_template
import os
from werkzeug.utils import secure_filename
from shutil import copyfile
from flask_bootstrap import Bootstrap

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
app.debug = True

bootstrap = Bootstrap(app)

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
    os.system("/usr/local/bin/hocr-pdf static/"+ file +"/ > /var/www/files.com/html/" + file + ".pdf")
    print("cd static/" + file + "; /usr/local/bin/hocr-split "+ file +".hocr page-%01d.hocr; cd ../..;")
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
    docs = [name for name in os.listdir(".") if os.path.isdir(name)]
    os.chdir("..")
    return render_template('borrar.html', form = form, links = docs)

if __name__ == "__main__":
    app.run()

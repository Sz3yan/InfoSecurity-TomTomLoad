import re
import pyotp
import smtplib
import json
import bcrypt 
import datetime

from random import *
from static.classes.config import CONSTANTS
from static.classes.unique_id import UniqueID
from static.classes.storage import GoogleCloudStorage
from static.security.session_management import TTLSession
from static.classes.form import Login, SignUp, Forget, Otp, EmailOtp
from flask import Blueprint, render_template, request, redirect, abort, url_for, session, flash


admin_user = Blueprint('admin_user', __name__, url_prefix="/user", template_folder="templates", static_folder='static')

ttlSession = TTLSession()
storage = GoogleCloudStorage()

storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.ACL_FILE_NAME, CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"))


# ------ Admin User ------
@admin_user.route("/login", methods=["POST", "GET"])
def api_admin_user_login():
    login = Login()

    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("adminuser.json"), "r") as f:
        adminuser = json.load(f)

        if login.validate_on_submit():
            email = login.email.data
            password = login.password.data
            
            existing_user = False
            for user in adminuser["Users"]:
                if user["email"] == email:
                    password_to_verify = password.encode('utf-8')
                    if bcrypt.checkpw(password_to_verify, user["password"].encode('utf-8')):
                        existing_user = True
                        break
                
            if email == "":
                return redirect(url_for('admin_user.api_admin_user_login'))
            if password == "":
                return redirect(url_for('admin_user.api_admin_user_signup'))

            if existing_user:
                session['email'] = email
                return redirect(url_for('admin_user.api_admin_user_choosetwofa'))
            else:
                flash('You have entered the wrong details. Please try again.', category='error')
                return redirect(url_for('admin_user.api_admin_user_login'))
                
    return render_template('user/login.html')


@admin_user.route("/signup", methods=["POST", "GET"])
def api_admin_user_signup():
    signup = SignUp(request.form)

    with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("adminuser.json"), "r") as f:
        adminuser = json.load(f)

        if signup.validate_on_submit() and request.method == 'POST':
            email = signup.email.data
            password = signup.password.data

            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

            if email == "":
                return redirect(url_for('admin_user.api_admin_user_signup'))
            if password == "":
                return redirect(url_for('admin_user.api_admin_user_signup'))
            
            time = datetime.datetime.now()

        #------ PASSWORD VALIDATION ------
            email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
            special_char_regex = re.compile('[$@#$%^&*]')
            
            if not email_regex.match(email):
                flash('Invalid email address', category='error')
                return redirect(url_for('admin_user.api_admin_user_signup'))
            elif len(password) < 8:
                flash('Password length should be at least 8', category='error')
                return redirect(url_for('admin_user.api_admin_user_signup'))
            elif len(password) > 20:
                flash('Password length should not be more than 20', category='error')
                return redirect(url_for('admin_user.api_admin_user_signup'))
            elif not any(char.isdigit() for char in password):
                flash('Password should have at least one numeral', category='error')
                return redirect(url_for('admin_user.api_admin_user_signup'))
            elif not any(char.isupper() for char in password):
                flash('Password should have at least one uppercase letter', category='error')
                return redirect(url_for('admin_user.api_admin_user_signup'))
            elif not any(char.islower() for char in password):
                flash('Password should have at least one lowercase letter', category='error')
                return redirect(url_for('admin_user.api_admin_user_signup'))
            elif not special_char_regex.search(password):
                flash('Password should have at least one special character', category='error')
                return redirect(url_for('admin_user.api_admin_user_signup'))

            existing_user = False
            for user in adminuser["Users"]:
                if user["email"] == email:
                    password_to_verify = password.encode('utf-8')
                    if bcrypt.checkpw(password_to_verify, user["password"].encode('utf-8')):
                        existing_user = True
                        break

            if existing_user:
                flash('Account has already been created', category='error')
            else:
                user_data = {'email': email, 'password': hashed_password.decode('utf-8'), 'created_at': time}
                adminuser['Users'].append(user_data)
                with open(CONSTANTS.TTL_CONFIG_FOLDER.joinpath("adminuser.json"), "w") as f:
                    json.dump(adminuser, f, default=str)

                storage.upload_blob(
                    bucket_name=CONSTANTS.STORAGE_BUCKET_NAME,
                    source_file_name=CONSTANTS.TTL_CONFIG_FOLDER.joinpath("adminuser.json"),
                    destination_blob_name="adminuser.json"
                )
                flash('Account successfully created', category='success')
                
    return render_template('user/signup.html')


@admin_user.route("/forget", methods=["POST", "GET"])
def api_admin_user_forget():

    return render_template('user/forget.html')

@admin_user.route("/choosetwofa")
def api_admin_user_choosetwofa():

    return render_template('user/choosetwofa.html')

@admin_user.route("/otp")
def api_admin_user_otp():
    shared_secret = pyotp.random_base32()
    return render_template('user/otp.html', shared_secret=shared_secret)


@admin_user.route("/otp", methods=["POST"])
def api_admin_user_otp_form():
    otp=Otp()
    
    if otp.validate_on_submit():
        totpval = str(otp.totpval.data) 
        shared_secret = str(otp.shared_secret.data)

        if pyotp.TOTP(shared_secret).verify(totpval):
            flash("The OTP is valid", category='success')
            #otp works so can remove flash and redirect to another page 
            #redirect(url_for('admin_user.api_admin_user_signup'))
        else:
            flash("The OTP is unvalid", category='error')
            return redirect(url_for('admin_user.api_admin_user_otp'))
            
    return render_template('user/otp.html', totpval=totpval)

@admin_user.route("/emailotp")
def api_admin_user_emailotp():
    email = session["email"]
    sender_email = 'tomtomloadcms@gmail.com'
    rec_email = email
    password = 'jixepnkykfebnkai'
    subject = 'One time password'
    otp = randint(100000,999999)
    session['otp'] = otp
    body = 'Your TomTomLoad CMS verification code is ' + str(otp) + '. Please use this to verify your account.'
    message = f'Subject: {subject}\n\n{body}'
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, rec_email, message)

    return render_template('user/emailotp.html', email=email)

    
@admin_user.route("/emailotp", methods=["POST"])
def api_admin_user_emailotp_now():
    emailotp = EmailOtp()
    current_user_otp = session['otp']
    
    if emailotp.validate_on_submit():
        onetimepass = emailotp.onetimepass.data

        if int(onetimepass) == int(current_user_otp):
            flash("The OTP is valid", category='success')
            #otp works so can remove flash and redirect to another page 
        else:
            flash("The OTP is unvalid. Please try again.", category='error')
            return redirect(url_for('admin_user.api_admin_user_emailotp'))
        
    return render_template('user/emailotp.html')
    
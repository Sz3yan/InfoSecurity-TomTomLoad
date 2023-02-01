import re
import pyotp
import random 

from static.classes.config import CONSTANTS
from static.classes.unique_id import UniqueID
from static.classes.storage import GoogleCloudStorage
from static.security.session_management import TTLSession
from static.classes.form import Login, SignUp, Forget, Otp
from flask import Blueprint, render_template, request, redirect, abort, url_for, session, flash


admin_user = Blueprint('admin_user', __name__, url_prefix="/user", template_folder="templates", static_folder='static')

ttlSession = TTLSession()
storage = GoogleCloudStorage()

storage.download_blob(CONSTANTS.STORAGE_BUCKET_NAME, CONSTANTS.ACL_FILE_NAME, CONSTANTS.TTL_CONFIG_FOLDER.joinpath("acl.json"))


# ------ Admin User ------
@admin_user.route("/login", methods=["POST", "GET"])
def api_admin_user_login():
    login = Login()
    details = {"email":"user@ttl.com", "password":"user"}
    if login.validate_on_submit():
        email = login.email.data
        password = login.password.data

        if email == details["email"] and password == details["password"]:
            return redirect(url_for('admin_user.api_admin_user_otp'))
  
        else:
            return redirect(url_for('admin_user.api_admin_user_login'))
            #try if it is successful if yes the redirect it to otp
            

    return render_template('user/login.html')


@admin_user.route("/signup", methods=["POST", "GET"])
def api_admin_user_signup():
    signup = SignUp()
    if signup.validate_on_submit():
        email = signup.email.data
        password = signup.password.data

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
        else:
            flash('Account successfully created.', category='success')
            
    return render_template('user/signup.html')


@admin_user.route("/forget", methods=["POST", "GET"])
def api_admin_user_forget():

    return render_template('user/forget.html')

# @admin_user.route("/mfa", method=["POST", "GET"])
# def api_admin_user_mfa():

#     return render_template('user/mfa.html')

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
            #redirect works so can remove flash and redirect to another page 
            #redirect(url_for('admin_user.api_admin_user_signup'))
        else:
            flash("The OTP is unvalid", category='error')
            return redirect(url_for('admin_user.api_admin_user_otp'))
            
    return render_template('user/otp.html', totpval=totpval)

@admin_user.route("/emailotp", methods=["POST", "GET"])
def api_admin_user_email():

    return render_template('user/emailotp.html')
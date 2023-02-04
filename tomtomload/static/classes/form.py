from flask_wtf import FlaskForm
from wtforms import StringField, validators, PasswordField

class Login(FlaskForm):
    email = StringField([validators.Length(min=1, max=30), validators.DataRequired()], render_kw={"placeholder": "Email"})
    password = PasswordField([validators.Length(min=8, max=15), validators.Regexp(regex="(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}"),
                        validators.DataRequired()], render_kw={"placeholder": "Password"})

class SignUp(FlaskForm):
    email = StringField([validators.Length(min=1, max=30), validators.DataRequired()], render_kw={"placeholder": "Email"})
    password = PasswordField([validators.Length(min=8, max=15), validators.Regexp(regex="(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}"),
                        validators.DataRequired()], render_kw={"placeholder": "Password"})

class Forget(FlaskForm):
    email = StringField([validators.Length(min=1, max=30), validators.DataRequired()], render_kw={"placeholder": "Email"})

class Otp(FlaskForm):
    shared_secret = StringField([validators.DataRequired()], render_kw={"placeholder": "Secret Key"})
    totpval = StringField([validators.DataRequired()], render_kw={"placeholder": "Otp"})

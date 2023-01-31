from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators, PasswordField
from wtforms.validators import DataRequired, ValidationError

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

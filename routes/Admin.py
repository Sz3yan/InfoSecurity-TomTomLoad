from static.classes.constants import CONSTANTS
from static.classes.firebase import Firebase
from flask import Blueprint, render_template, request, session, redirect, url_for


admin = Blueprint('admin', __name__, url_prefix='/admin', static_folder="static", template_folder="template")


@admin.route('/')
def hi():
    return render_template('admin/dashboard.html')


@admin.route('/logout')
def logout():
    return render_template('admin/logout.html')


@admin.route('/media')
def media():
    return render_template('admin/media.html')


@admin.route('/media/<id>')
def media_id(id):
    return render_template('admin/media_id.html')


@admin.route('/posts')
def post():
    return render_template('admin/post.html')


@admin.route('/posts/<id>')
def post_id(id):
    return render_template('admin/post_id.html')
import requests
import socket
from flask import Blueprint, render_template, session, redirect

authorised_user = Blueprint('authorised_user', __name__, template_folder="templates", static_folder='static')


# create a wrapper that checks if the user is logged in
# def signed_token(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if session.get("user_id") is None:
#             return redirect("/login")
#         return f(*args, **kwargs)
#     return decorated_function


# def server_program():
#     print("hi")
#     host = socket.gethostname()
#     port = 5001

#     server_socket = socket.socket()  # get instance

#     try:
#         server_socket.bind((host, port))  # bind host address and port together

#         # configure how many client the server can listen simultaneously
#         server_socket.listen()
#         conn, address = server_socket.accept()  # accept new connection
#         print("Connection from: " + str(address))

#         # print message from client
#         data = conn.recv(1024).decode()
#         print("from connected user: " + str(data))

#         conn.close()  # close the connection
#     except:
#         print("Error")

# server_program()


@authorised_user.route('/')
def home():    
    return render_template('authorised_admin/dashboard.html')


@authorised_user.route("/logout")
def logout():
    session.clear()
    return redirect("https://127.0.0.1:8080/")

from __init__ import app 



from create import auth_routes
app.register_blueprint(auth_routes)

from route import routes
app.register_blueprint(routes)

if __name__ == "__main__":
    app.run(debug=True)


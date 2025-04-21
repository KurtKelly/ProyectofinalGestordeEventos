from app import create_app

app = create_app()
app.config['SECRET_KEY'] = 'mi_clave_secreta_única_y_segura'


if __name__ == "__main__":
    app.run(debug=True)


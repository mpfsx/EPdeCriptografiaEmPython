# Importação de bibliotecas
import os  # Biblioteca para manipulação de diretórios
from flask import Flask, request, make_response  # Importa classes essenciais do Flask
from flask_sqlalchemy import SQLAlchemy  # Importa extensão SQLAlchemy para integração com banco de dados

# Criação de uma instância do Flask
app = Flask(__name__)  # Cria uma instância da aplicação Flask
basedir = os.path.abspath(os.path.dirname(__file__))  # Obtém o caminho absoluto do diretório atual

# Configuração do aplicativo Flask
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'db.sqlite3'),  # Configura o URI do banco de dados
    SQLALCHEMY_TRACK_MODIFICATIONS=False,  # Desativa o rastreamento de modificações no SQLAlchemy
    FLASK_APP='server',  # Configuração do Flask
)

# Inicialização da extensão SQLAlchemy
db = SQLAlchemy(app)  # Inicializa a extensão SQLAlchemy com a instância do Flask
debug = True  # Ativa o modo de depuração

# Definição do modelo de dados
class User(db.Model):  # Define uma classe de modelo para usuários
    id = db.Column(db.Integer, primary_key=True)  # Campo de identificação único
    username = db.Column(db.String(140), unique=True, nullable=False)  # Campo para nome de usuário
    email = db.Column(db.String(140), unique=True, nullable=False)  # Campo para endereço de e-mail
    password = db.Column(db.String(140), nullable=False)  # Campo para senha

# Criação das tabelas no banco de dados
with app.app_context():
    db.create_all()  # Cria as tabelas no banco de dados

# Função utilitária para gerar cabeçalhos HTML
def get_header(title):  # Define uma função para gerar cabeçalhos HTML
    return (
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
        </head>
        """
    )

# Controladores para páginas HTML
def get_homepage():  # Define um controlador para a página inicial
    return make_response(
        get_header('EP4 | Redes') +
        """
        <body>
            <h1>Redes Industriais</h1>
            <h2>Criptografia com Flask</h2>
            <br/>
            <a href="signup">Sign Up</a>
        </body>
        """, 200
    )

def get_signup():  # Define um controlador para a página de cadastro
    return make_response(
        get_header('EP4 | Sign Up') +
        """
        <body>
            <h1>Sign Up</h1>
            <form action="/signup" method="post"/>
                <input name="username" id="username" placeholder="Username *" type="text"/>
                <br/>
                <input name="email" id="email" placeholder="E-mail *" type="email"/>
                <br/>
                <input name="password" id="password" placeholder="Password *" type="password"/>
                <br/><br/>
                <input id="submit" type="submit" value="Sign Up"/>
            </form>
            <br/>
            <a href="/">Back</a>
        </body>
        """, 200
    )

# Controlador para o cadastro de usuários
def post_signup():  # Define um controlador para o cadastro de usuários
    for field in request.form.keys():
        if not request.form[field]:
            return make_response(f'<b>{field.title()}</b> is required!', 400)

    same_username_user = User.query.filter_by(username=request.form['username']).first()
    same_email_user = User.query.filter_by(email=request.form['email']).first()

    if same_username_user or same_email_user:
        return make_response('User already exists!', 400)

    db.session.add(User(
        username=request.form['username'],
        email=request.form['email'],
        password=request.form['password']
    ))
    db.session.commit()
    return make_response('User created!', 201)

# Rotas do aplicativo
@app.route('/')
def get_landpage():  # Define uma rota para a página inicial
    return get_homepage()

@app.route('/signup', methods=['GET', 'POST'])
def handle_signup():  # Define uma rota para o cadastro de usuários
    if request.method == 'GET':
        return get_signup()
    if request.method == 'POST':
        return post_signup()

    return make_response(f"Can't {request.method}/signup", 405)

# Inicialização do aplicativo Flask
if __name__ == "__main__":
    app.run(debug=debug)  # Inicia a aplicação Flask em modo de depuração

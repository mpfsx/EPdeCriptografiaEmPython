# Importa a classe Flask do módulo flask
from flask import Flask

# Importa a classe SQLAlchemy do módulo flask_sqlalchemy
from flask_sqlalchemy import SQLAlchemy

# Importa o módulo os para trabalhar com funcionalidades do sistema operacional
import os

# Cria uma instância da aplicação Flask
app = Flask(__name__)

# Obtém o caminho absoluto para o diretório do script em execução
basedir = os.path.abspath(os.path.dirname(__file__))

# Configurações da aplicação Flask
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3') # Define a URI do banco de dados SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Desativa o rastreamento de modificações no SQLAlchemy
app.config['FLASK_APP'] = 'server' # Define o nome do aplicativo Flask como 'server'

# Inicializa uma instância do SQLAlchemy para interagir com o banco de dados
db = SQLAlchemy(app)

# Ativa o modo de depuração, útil durante o desenvolvimento para obter informações detalhadas sobre erros
debug = True

# Definindo a classe do modelo de usuário
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Campo de identificação, chave primária
    username = db.Column(db.String(140), unique=True, nullable=False)  # Campo para o nome de usuário, único e obrigatório
    password = db.Column(db.String(140), nullable=False)  # Campo para a senha, obrigatório
    email = db.Column(db.String(140), unique=True, nullable=False)  # Campo para o endereço de email, único e obrigatório

# Contexto de aplicação para criar as tabelas no banco de dados
with app.app_context():
    # Criando todas as tabelas
    db.create_all()

# Função que gera o cabeçalho HTML com o título fornecido.
def obter_cabecalho(titulo):
    # Retorno do cabeçalho HTML formatado.
    return (
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{titulo}</title>
        </head>
        """
    )

# Função que retorna a página inicial.
def obter_pagina_inicial():
    # Monta a resposta HTTP com o cabeçalho e o corpo da página.
    return make_response(
        get_header('EP4 | Redes') +
        """
        <body>
            <h1>EP4 de Redes</h1>
            <h2>Criptografia</h2>
            <br />
            <a href="signup">Sign Up</a>
        </body>
        """, 200
    )

# Função que retorna a página de cadastro.
def obter_pagina_cadastro():
    # Monta a resposta HTTP com o cabeçalho e o corpo da página.
    return make_response(
        get_header('EP4 | Sign Up') +
        """
        <body>
            <h1>Sign Up</h1>
            <form action="/signup" method="post"/>
                <input name="username" id="username" placeholder="Username *" type="text" />
                <br />
                <input name="email" id="email" placeholder="E-mail *" type="email" />
                <br />
                <input name="password" id="password" placeholder="Password *" type="password" />
                <br />
                <br />
                <input id="submit" type="submit" value="Sign Up" />
            </form>
            <br />
            <a href="/"> < Back </a>
        </body>
        """, 200
    )

# Função que processa o cadastro.
def cadastrar_usuario():
    # Itera sobre os campos do formulário e verifica se estão preenchidos.
    for campo in request.form.keys():
        if not request.form[campo]:
            return make_response(f'<b>{campo.title()}</b> é obrigatório!', 400)

    # Verifica se o usuário ou o e-mail já existem no banco de dados.
    mesmo_usuario_nome = User.query.filter_by(username=request.form['username']).first()
    mesmo_usuario_email = User.query.filter_by(email=request.form['email']).first()

    if mesmo_usuario_nome or mesmo_usuario_email:
        return make_response('Usuário já existe!', 400)

    # Adiciona o novo usuário ao banco de dados.
    db.session.add(User(
        username=request.form['username'],
        email=request.form['email'],
        password=request.form['password']
    ))
    db.session.commit()

    return make_response('Usuário criado!', 201)

# Rota para a página inicial ("/").
@app.route('/')
def obter_pagina_inicial():
    # Chama a função que retorna a página inicial.
    return obter_pagina_inicial()

# Rota para lidar com a página de cadastro ("/signup").
@app.route('/signup', methods=['GET', 'POST'])
def lidar_com_cadastro():
    # Se o método da requisição for GET, chama a função que retorna a página de cadastro.
    if request.method == 'GET':
        return obter_pagina_cadastro()
    # Se o método da requisição for POST, chama a função que processa o cadastro.
    elif request.method == 'POST':
        return cadastrar_usuario()

    # Se a requisição não for nem GET nem POST, retorna uma resposta indicando o erro.
    return make_response(f"Não é possível {request.method} /signup", 405)

# Inicia a aplicação Flask com o modo de depuração ativado
app.run(debug=debug)


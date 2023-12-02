# Importação de bibliotecas
import os  # Biblioteca para manipulação de diretórios
from flask_sqlalchemy import SQLAlchemy  # Importa extensão SQLAlchemy para integração com banco de dados
from flask import Flask, request, make_response, redirect, abort  # Importa classes essenciais do Flask

#imports Parte 1.3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
from hashlib import md5
from base64 import b64encode , b64decode

#segurança e à geração de chaves aleatória
SESSION_ID_SIZE=16 #Define o tamanho (em bytes) do identificador de sessão (session_id)
SALT_SIZE=16 #Define o tamanho (em bytes) do "salt" (sal) que é uma sequência aleatória única usada para fortalecer a segurança de senhas

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

# Define a classe Session que herda de db.Model
class Session(db.Model):
    # Define o campo id como uma chave primária de tipo String com tamanho definido
    id = db.Column(db.String(SESSION_ID_SIZE), primary_key=True)
    
    # Define o campo user_id como uma chave estrangeira referenciando o campo id da tabela User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Define o campo created_at como uma coluna de data e hora com valor padrão
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

# Criação das tabelas no banco de dados
with app.app_context():
    db.create_all()  # Cria as tabelas no banco de dados


# Função utilitária para gerar cabeçalhos HTML

# Função para gerar cabeçalhos HTML
def get_header(title):
    return (
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            <style>
                body {{
                    background-color: #f0f0f0;
                    font-family: Arial, sans-serif;
                }}
                div {{
                    max-width: 600px;
                    margin: auto;
                    background-color: #fff;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    color: #333;
                }}
                form {{
                    width: 100%;
                }}
                input {{
                    width: 100%;
                    padding: 10px;
                    margin-bottom: 10px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                }}
                #submit {{
                    background-color: #3498db;
                    color: #fff;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                }}
                a {{
                    text-decoration: none;
                    color: #777;
                }}
            </style>
        </head>
        """
    )




# Função para obter o usuário dos cookies

def get_user_from_cookies():
    curr_session_id = request.cookies.get('session_id')

    if curr_session_id:
        curr_session = Session.query.get(curr_session_id)

        if curr_session:
            user_id = curr_session.user_id  #conforme a estrutura do modelo Session
            user = User.query.get(user_id)

            # Obtém a última sessão do usuário
            user_last_session = Session.query.filter_by(user_id=user_id).order_by(Session.created_at.desc()).first()

            # Verifica se a última sessão do usuário é igual à sessão atual
            if user_last_session == curr_session:
                return user

    return None


# Função para converter array de bytes para base64
def bytearr_to_b64(bytearr):
    return b64encode(bytearr).decode('ascii')

# Função para converter base64 para array de bytes
def b64_to_bytearr(b64):
    return b64decode(b64.encode('ascii'))

# Função para verificar se a senha está correta usando o algoritmo de derivação de chave
def is_correct_password(kdf, password_bytes, digest):
    try:
        kdf.verify(password_bytes, digest)
        return True
    except InvalidKey:
        return False

# Função para criar uma nova sessão no banco de dados
def create_session(user_id):
    # Gera um ID de sessão usando MD5 e converte para base64
    session_id = bytearr_to_b64(md5(os.urandom(SESSION_ID_SIZE)).digest())

    # Cria uma nova sessão associada ao usuário
    new_session = Session(id=session_id, user_id=user_id)
    db.session.add(new_session)
    db.session.commit()

    # Cria uma resposta de redirecionamento para a página de perfil e define o cookie da sessão
    res = make_response(redirect('/profile'), 302)
    res.set_cookie('session_id', session_id)

    # Imprime informações para depuração
    print('\nLogin do Usuario:')
    print('session ID:', session_id, end='\n\n')

    return res

# Função para inicializar o algoritmo de derivação de chave (Key Derivation Function - KDF)
def init_kdf(salt=None):
    # Gera um sal aleatório se nenhum sal for fornecido
    salt = salt or os.urandom(SALT_SIZE)

    # Inicializa o algoritmo de derivação de chave Scrypt com os parâmetros especificados
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend()), salt




# Controlador para a página inicial

def get_homepage():
    return make_response(
        get_header('EP4 | Redes') +
        """
        <body>
            <div>
                <h1>Redes Industriais</h1>
                <h2>Criptografia com Flask</h2>
                <br/>
                <a href="signup">Sign Up</a>
            </div>
        </body>
        """, 200
    )

# Controlador para a página de cadastro
def get_signup():
    return make_response(
        get_header('EP4 | Sign Up') +
        """
        <body>
            <div>
                <h1>Sign Up</h1>
                <form action="/signup" method="post">
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
            </div>
        </body>
        """, 200
    )

# Função para processar o cadastro de usuário (POST)
def post_signup():
    # Itera sobre os campos do formulário
    for field in request.form.keys():
        # Verifica se todos os campos foram preenchidos
        if not request.form[field]:
            # Retorna uma resposta indicando que o campo é obrigatório
            return make_response(f'<b>{field.title()}</b> is required!', 400)

    # Verifica se já existe um usuário com o mesmo nome de usuário ou e-mail
    same_username_user = User.query.filter_by(username=request.form['username']).first()
    same_email_user = User.query.filter_by(email=request.form['email']).first()

    if same_username_user or same_email_user:
        # Retorna uma resposta indicando que o usuário já existe
        return make_response('User already exists!', 400)

    # Inicializa o algoritmo de derivação de chave (KDF) e obtém o digest da senha
    kdf, salt = init_kdf()
    digest = kdf.derive(request.form['password'].encode('utf-8'))

    # Adiciona o novo usuário ao banco de dados
    db.session.add(User(
        username=request.form['username'],
        email=request.form['email'],
        password=bytearr_to_b64(salt + digest)
    ))
    db.session.commit()

    # Imprime informações para depuração
    print('\nO Usuário que foi cadastrado:')
    print('i) Senha original:', request.form['password'])
    print('ii) Sal:', salt.hex(), '| Digest:', digest.hex())
    print('iii) Salvo no sqlite3:', bytearr_to_b64(salt + digest), end='\n\n')

    # Retorna uma resposta indicando que o usuário foi criado com sucesso
    return make_response('User created!', 201)


# Função para obter a página de login (GET)
def get_signin():
    return make_response(
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>EP4 | Sign In</title>
            <style>
                body {{
                    background-color: #f0f0f0;
                    font-family: Arial, sans-serif;
                }}
                form {{
                    max-width: 600px;
                    margin: auto;
                    background-color: #fff;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    color: #333;
                }}
                input {{
                    width: 100%;
                    padding: 10px;
                    margin-bottom: 10px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                }}
                #submit {{
                    background-color: #3498db;
                    color: #fff;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                }}
                a {{
                    text-decoration: none;
                    color: #777;
                }}
            </style>
        </head>
        <body>
            <h1>Sign In</h1>
            <form action="/signin" method="post">
                <input name="email" id="email" placeholder="E-mail *" type="email" required/>
                <br/>
                <input name="password" id="password" placeholder="Password *" type="password" required/>
                <br/><br/>
                <input id="submit" type="submit" value="Sign In"/>
            </form>
            <br/>
            <a href="/">Back</a>
        </body>
        </html>
        """, 200
    )



# Função para processar o login (POST)
def post_signin():
    # Itera sobre os campos do formulário
    for field in request.form.keys():
        # Verifica se todos os campos foram preenchidos
        if not request.form[field]:
            # Retorna uma resposta indicando que o campo é obrigatório
            return make_response(f'<b>{field.title()}</b> is required!', 400)

    # Verifica se o usuário está registrado no banco de dados
    registered_user = User.query.filter_by(
        email=request.form['email'],
    ).first()

    if registered_user:
        # Obtém o hash armazenado no banco de dados
        stored_hash_bytes = b64_to_bytearr(registered_user.password)
        stored_salt = stored_hash_bytes[:SALT_SIZE]
        stored_digest = stored_hash_bytes[SALT_SIZE:]

        # Obtém a senha enviada no formulário
        sent_password_bytes = request.form['password'].encode('utf-8')

        # Inicializa o KDF com o sal armazenado
        kdf, _ = init_kdf(stored_salt)

        # Verifica se a senha está correta
        if is_correct_password(kdf, sent_password_bytes, stored_digest):
            # Cria uma nova sessão para o usuário logado
            return create_session(str(registered_user.id))
        else:
            # Retorna uma resposta indicando que a senha está incorreta
            return make_response('Incorrect password!', 401)

    # Retorna uma resposta indicando que o usuário não foi encontrado
    return make_response('User not found!', 401)


# Função para obter a página de perfil (GET)
def get_profile():
    logged_user = get_user_from_cookies()

    if logged_user:
        return make_response(
            f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>EP4 | Profile</title>
                <style>
                    body {{
                        background-color: #f0f0f0;
                        font-family: Arial, sans-serif;
                    }}
                    div {{
                        max-width: 600px;
                        margin: auto;
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }}
                    h1, p, ul {{
                        color: #333;
                    }}
                    ul {{
                        list-style-type: none;
                        padding: 0;
                    }}
                    li {{
                        margin-bottom: 10px;
                    }}
                    a {{
                        text-decoration: none;
                        color: #3498db;
                    }}
                </style>
            </head>
            <body>
                <div>
                    <h1>Profile</h1>
                    <p>Signed in as: <b>{logged_user.username}</b></p>
                    <ul>
                        <li><a href="/">Home</a></li>
                        <li><a href="/logout">Logout</a></li>
                    </ul>
                </div>
            </body>
            </html>
            """, 200
        )

    return abort(401, description="User not logged in!")


# Função para obter a página de logout (GET)
def get_logout():
    logged_user = get_user_from_cookies()

    if logged_user:
        return make_response(
            f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>EP4 | Logout</title>
                <style>
                    body {{
                        background-color: #f0f0f0;
                        font-family: Arial, sans-serif;
                    }}
                    div {{
                        max-width: 600px;
                        margin: auto;
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }}
                    h1, p {{
                        color: #333;
                    }}
                    div form {{
                        display: flex;
                    }}
                    input {{
                        background-color: #3498db;
                        color: #fff;
                        border: none;
                        padding: 8px 16px;
                        cursor: pointer;
                    }}
                    #back {{
                        background-color: #3498db;
                        margin-right: 10px;
                    }}
                    #logout {{
                        background-color: #e74c3c;
                    }}
                    a {{
                        text-decoration: none;
                        color: #777;
                    }}
                </style>
            </head>
            <body>
                <div>
                    <h1>Logout</h1>
                    <p>Signed in as: <b>{logged_user.username}</b></p>
                    <p>Do you really want to logout?</p>
                    <div>
                        <form action="/profile" method="get" id="back">
                            <input type="submit" value="Back">
                        </form>
                        <form action="/logout" method="post" id="logout">
                            <input type="submit" value="Logout">
                        </form>
                    </div>
                </div>
            </body>
            </html>
            """, 200
        )

    return abort(401, description="User not logged in!")



# Função para processar o logout (POST)
def post_logout():
    # Cria uma resposta de redirecionamento para a página inicial e remove o cookie do ID da sessão
    res = make_response(redirect('/'), 302)
    res.set_cookie('session_id', '', max_age=0)
    return res





# Rota para a página inicial
@app.route('/')
def get_landpage():
    return get_homepage()

# Rota para lidar com o cadastro (GET e POST)
@app.route('/signup', methods=['GET', 'POST'])
def handle_signup():
    # Se o método da requisição for GET, chama a função get_signup
    if request.method == 'GET':
        return get_signup()
    # Se o método da requisição for POST, chama a função post_signup
    if request.method == 'POST':
        return post_signup()
    # Se o método da requisição não for GET nem POST, retorna uma resposta indicando o erro 405
    return make_response(f"Can't {request.method}/signup", 405)

# Rota para lidar com o login (GET e POST)
@app.route('/signin', methods=['GET', 'POST'])
def handle_signin():
    # Se o método da requisição for GET, chama a função get_signin
    if request.method == 'GET':
        return get_signin()
    # Se o método da requisição for POST, chama a função post_signin
    if request.method == 'POST':
        return post_signin()
    # Se o método da requisição não for GET nem POST, retorna uma resposta indicando o erro 405
    return make_response(f"Can't {request.method}/signin", 405)

# Rota para a página de perfil
@app.route('/profile')
def get_user():
    return get_profile()

# Rota para lidar com o logout (GET e POST)
@app.route('/logout', methods=['GET', 'POST'])
def handle_logout():
    # Se o método da requisição for GET, chama a função get_logout
    if request.method == 'GET':
        return get_logout()
    # Se o método da requisição for POST, chama a função post_logout
    if request.method == 'POST':
        return post_logout()
    # Se o método da requisição não for GET nem POST, retorna uma resposta indicando o erro 405
    return make_response(f"Can't {request.method}/logout", 405)




# Inicialização do aplicativo Flask

if __name__ == "__main__":
    app.run(debug=debug)  # Inicia a aplicação Flask em modo de depuração

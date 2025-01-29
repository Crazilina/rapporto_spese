from flask import Flask, redirect, url_for, request, session
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from modelli import db, Utente
from routes import routes, get_meta
from configparser import ConfigParser
from datetime import datetime, date
from werkzeug.security import generate_password_hash
import os
import logging

# --- Logging setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Costanti per il caricamento dei file ---
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

# Funzione per controllare il formato valido del file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Lettura configurazione da configuration.ini
def leggi_config():
    """
    Legge la configurazione dalle variabili di ambiente o dal file configuration.ini.
    """
    parser = ConfigParser()

    # Prova a leggere il file se esiste
    if os.path.exists('configuration.ini'):
        parser.read('configuration.ini')

    try:
        # Prima di tutto, recupera i parametri dalle variabili di ambiente se sono impostati
        db_params = {
            'host': os.getenv('DB_HOST') or parser.get('postgresql', 'host', fallback=None),
            'database': os.getenv('DB_NAME') or parser.get('postgresql', 'database', fallback=None),
            'user': os.getenv('DB_USER') or parser.get('postgresql', 'user', fallback=None),
            'password': os.getenv('DB_PASSWORD') or parser.get('postgresql', 'password', fallback=None),
            'port': os.getenv('DB_PORT') or parser.get('postgresql', 'port', fallback='5432'),
        }

        mail_params = {
            'MAIL_SERVER': os.getenv('EMAIL_HOST') or parser.get('mail', 'EMAIL_HOST', fallback=None),
            'MAIL_PORT': int(os.getenv('EMAIL_PORT') or parser.get('mail', 'EMAIL_PORT', fallback=587)),
            'MAIL_USERNAME': os.getenv('EMAIL_HOST_USER') or parser.get('mail', 'EMAIL_HOST_USER', fallback=None),
            'MAIL_PASSWORD': os.getenv('EMAIL_HOST_PASSWORD') or parser.get('mail', 'EMAIL_HOST_PASSWORD', fallback=None),
            'MAIL_USE_TLS': os.getenv('EMAIL_USE_TLS') == 'True' or parser.getboolean('mail', 'EMAIL_USE_TLS', fallback=False),
            'MAIL_USE_SSL': os.getenv('EMAIL_USE_SSL') == 'True' or parser.getboolean('mail', 'EMAIL_USE_SSL', fallback=False),
        }

        app_params = {
            'SECRET_KEY': os.getenv('SECRET_KEY') or parser.get('app', 'SECRET_KEY', fallback=None),
        }

        return {
            'SQLALCHEMY_DATABASE_URI': f"postgresql://{db_params['user']}:{db_params['password']}@{db_params['host']}:{db_params['port']}/{db_params['database']}",
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            **mail_params,
            **app_params,
        }
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        raise


# Creazione dell'app Flask
app = Flask(__name__)
try:
    app.config.update(leggi_config())
except Exception as e:
    logger.critical(f"Critical error while loading configuration: {e}")
    raise

# Configurazione per il caricamento dei file
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite a 16 MB

# Inizializzazione di Flask-Mail
mail = Mail(app)

# Protezione CSRF
csrf = CSRFProtect(app)

# Assicurati che la cartella di upload esista
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Inizializzazione delle migrazioni
db.init_app(app)
migrate = Migrate(app, db)

# --- Registrazione delle rotte ---
app.register_blueprint(routes)

# --- Flask-Login ---
login_manager = LoginManager(app)
login_manager.login_view = 'routes.index'  # Redirect alla pagina di login

@login_manager.user_loader
def load_user(user_id):
    try:
        user = Utente.query.get(int(user_id))
        if not user:
            logger.warning(f"Failed to load user. ID: {user_id}")
        return user
    except ValueError:
        logger.error(f"Invalid user ID: {user_id}")
        return None
    except Exception as e:
        logger.error(f"Error loading user with ID {user_id}: {e}")
        return None


# --- Filtri aggiuntivi per Jinja ---
@app.template_filter('get_type_name')
def get_type_name(column_type):
    return type(column_type).__name__

@app.template_filter('format_date')
def format_date(value):
    if isinstance(value, (datetime, date)):
        return value.strftime('%d-%m-%Y')
    return value

def format_model_name(model):
    """Converte il nome del modello in un formato leggibile."""
    return model.replace('_', ' ').title()


# Registrazione delle funzioni globali
app.jinja_env.filters['get_type_name'] = get_type_name
app.jinja_env.filters['format_date'] = format_date
app.jinja_env.globals['get_meta'] = get_meta
app.jinja_env.filters['format_model_name'] = format_model_name

# --- CLI per creare un superutente ---
@app.cli.command('create-superuser')
def create_superuser():
    """Creazione di un superutente."""
    print("Creazione di un superutente")
    nome = input("Nome utente: ").strip()
    email = input("Email: ").strip()
    password = input("Password: ").strip()

    if not nome or not email or not password:
        print("Errore: Nome, email e password sono obbligatori.")
        return

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Controllo esistenza email
    try:
        existing_user = Utente.query.filter_by(email=email).first()
        if existing_user:
            print(f"Errore: Un utente con l'email {email} esiste già.")
            return

        # Creazione del superutente
        superuser = Utente(nome=nome, email=email, password_hash=hashed_password, ruolo='superuser', azienda_id=None)
        db.session.add(superuser)
        db.session.commit()
        print(f"Superutente {nome} creato con successo!")
    except Exception as e:
        logger.error(f"Error creating superuser: {e}")
        print("Si è verificato un errore durante la creazione del superutente.")

# --- Punto d'ingresso ---
if __name__ == "__main__":
    app.run(debug=False)
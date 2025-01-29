from flask import Blueprint, request, redirect, url_for, render_template, abort, current_app, flash, session
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from modelli import db, Azienda, Utente, Lavoratore, CategoriaSpesa, Spesa
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import smtplib
import re
from sqlalchemy.exc import IntegrityError
from datetime import date, datetime
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)

# --- Dizionario che collega i nomi dei modelli alle loro classi ---
MODELS = {
    "aziende": Azienda,
    "utenti": Utente,
    "lavoratori": Lavoratore,
    "categorie_spese": CategoriaSpesa,
    "spese": Spesa,
}

VALUTE = ["EUR", "USD", "RUB"]
STATI = ["Richiesta di Rimborso", "Pagato", "Approvato", "Rimborsato"]
METODI_PAGAMENTO = ["Carta aziendale", "Carta personale", "Contanti", "Bonifico"]
RUOLI = ('user', 'admin', 'superuser')  # Ruoli definiti

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}  # Formati di file consentiti

# --- Funzioni utilitarie ---
def allowed_file(filename):
    """Verifica se il file ha un'estensione consentita."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --- Creazione di un blueprint per le rotte ---
routes = Blueprint('routes', __name__)

# --- Inizializzazione di Flask-Mail ---
mail = Mail()
s = URLSafeTimedSerializer('secret_key')


def save_uploaded_file(file, upload_folder):
    """Salva un file caricato e restituisce il percorso relativo."""
    filename = secure_filename(file.filename)
    relative_path = os.path.join('uploads', filename)
    absolute_path = os.path.join(upload_folder, filename)
    file.save(absolute_path)
    return relative_path

def transform_data(data, model_class):
    """
    Trasforma i dati del modulo nei tipi corrispondenti per il modello.
    """
    transformed_data = {}
    for column in model_class.__table__.columns:
        if column.name in data:
            try:
                value = data[column.name]

                if column.type.python_type == int:
                    transformed_data[column.name] = int(value) if value else None
                elif column.type.python_type == float:
                    # Sostituisce la virgola con un punto prima della conversione
                    value = value.replace(',', '.') if value else None
                    transformed_data[column.name] = float(value) if value else None
                elif column.type.python_type == Decimal:
                    # Sostituisce la virgola con un punto prima della conversione
                    value = value.replace(',', '.') if value else None
                    transformed_data[column.name] = Decimal(value) if value else None
                elif column.type.python_type == datetime.date:
                    transformed_data[column.name] = (
                        datetime.strptime(value, "%Y-%m-%d").date() if value else None
                    )
                else:
                    transformed_data[column.name] = value
            except (ValueError, Decimal.InvalidOperation) as e:
                raise ValueError(f"Error converting field {column.name}: {e}")
    return transformed_data


def get_meta(model_name, attr):
    """
    Recupera un attributo meta di un modello, come singular, plural o gender.
    """
    model_class = MODELS[model_name]
    return getattr(model_class.Meta, attr, None)


def invia_email(email, subject, body):
    """
    Invia un'email a un destinatario specifico.

    :param email: Indirizzo email del destinatario.
    :param subject: Oggetto dell'email.
    :param body: Corpo del messaggio email.
    """
    try:
        msg = Message(
            subject=subject,
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = body
        mail.send(msg)
        current_app.logger.info(f"Email sent to {email}")
    except Exception as e:
        current_app.logger.error(f"Error sending email: {e}")


def invia_email_confirm(email, confirmation_url):
    """
    Invia un'email di conferma dell'indirizzo email con un link.

    :param email: Indirizzo email del destinatario.
    :param confirmation_url: Link per confermare l'indirizzo email.
    """
    body = (
        f"Ciao,\n\n"
        f"Per confermare il tuo indirizzo email, clicca qui:\n"
        f"{confirmation_url}\n\n"
        f"Grazie,\nIl Team."
    )
    invia_email(email, "Conferma il tuo indirizzo email", body)


def invia_email_registrazione(email, registration_url):
    """
    Invia un'email di registrazione a un collaboratore con un link.

    :param email: Indirizzo email del destinatario.
    :param registration_url: Link per completare la registrazione.
    """
    body = (
        f"Ciao,\n\n"
        f"Sei stato aggiunto come collaboratore.\n"
        f"Per completare la tua registrazione, clicca qui:\n"
        f"{registration_url}\n\n"
        f"Grazie,\nIl Team."
    )
    invia_email(email, "Completa la tua registrazione", body)


def has_access_to_model(model, item=None, action=None):
    """
    Verifica i permessi di accesso a un modello o a una voce specifica
    per l'utente corrente.

    :param model: Nome del modello da verificare.
    :param item: Oggetto della voce specifica (opzionale).
    :param action: Azione richiesta (view, edit, delete, create).
    :return: True se l'utente ha accesso, False altrimenti.
    """
    try:
        # Superuser: accesso solo ai modelli Utenti e Aziende, senza creazione
        if current_user.ruolo == 'superuser':
            if model not in ['utenti', 'aziende']:
                logger.warning(f"Superuser access denied to model: {model}")
                return False
            if action == 'create':
                logger.warning(f"Superuser access denied to create in model: {model}")
                return False
            logger.info(f"Superuser access granted to model: {model}, Action: {action}")
            return True

        # Amministratore
        if current_user.ruolo == 'admin':
            if model in ['utenti', 'aziende']:
                logger.warning(f"Admin access denied to model: {model}")
                return False
            if item and hasattr(item, 'azienda_id') and item.azienda_id != current_user.azienda_id:
                logger.warning(f"Admin access denied. Model: {model}, Item Azienda ID: {item.azienda_id}, User Azienda ID: {current_user.azienda_id}")
                return False
            logger.info(f"Admin access granted. Model: {model}, Action: {action}")
            return True

        # Utente
        if current_user.ruolo == 'user':
            if model in ['utenti', 'aziende']:
                logger.warning(f"User access denied to model: {model}")
                return False

            if model == 'lavoratori':
                if action in ['view', 'detail']:
                    if item is None or (item and item.azienda_id == current_user.azienda_id):
                        logger.info(f"User access granted to lavoratori. Action: {action}")
                        return True
                if action == 'edit':
                    # L'utente può modificare solo i propri dati
                    if item and item.utente_id == current_user.id:
                        logger.info(f"User access granted to edit lavoratori. User: {current_user.id}, Item: {item}")
                        return True
                    logger.warning(f"User access denied to edit lavoratori. User: {current_user.id}, Item: {item}")
                    return False
                logger.warning(f"User access denied to lavoratori. Action: {action}, Item: {item}")
                return False

            if model == 'categorie_spese':
                if action in ['view', 'detail']:
                    # Accesso alla lista e ai dettagli delle categorie consentito a tutti gli utenti
                    logger.info(f"User access granted to categorie_spese. Action: {action}, User: {current_user.id}")
                    return True

                # Azioni come edit, delete, create vietate agli utenti con ruolo user
                if action in ['edit', 'delete', 'create']:
                    logger.warning(f"User access denied to modify categorie_spese. Action: {action}, User: {current_user.id}")
                    return False

                logger.warning(f"Undefined action for categorie_spese. Action: {action}, User: {current_user.id}")
                abort(403)

            if model == 'spese':
                if action == 'create':
                    return True
                if action in ['edit', 'delete']:
                    if item and item.owner != current_user.id:
                        logger.warning(f"User access denied to spese. Action: {action}, Item Owner: {item.owner}, Current User: {current_user.id}")
                        return False
                    return True
                if action in ['view', 'detail']:
                    # Verifica se il proprietario della voce corrisponde all'utente
                    if item and item.owner != current_user.id:
                        logger.warning(f"User access denied to view spese. Item Owner: {item.owner}, Current User: {current_user.id}")
                        return False
                    logger.info(f"User access granted to spese. Action: {action}, User: {current_user.id}")
                    return True

        # Ruolo non definito
        logger.warning(f"Access denied. Undefined role or action. Model: {model}, Action: {action}")
        abort(403)
    except Exception as e:
        logger.error(f"Error in access control. Model: {model}, Action: {action}, Error: {e}")
        abort(403)



# --- Validazione email ---
def is_valid_email(email):
    """
    Verifica se un'email è conforme a un formato corretto.

    :param email: Indirizzo email da validare.
    :return: True se l'email è valida, False altrimenti.
    """
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(email_regex, email)


def validate_password(password):
    """
    Verifica se una password soddisfa i requisiti di sicurezza.

    :param password: Stringa della password da verificare.
    :return: None se la password è valida, altrimenti un messaggio di errore.
    """
    if len(password) < 8:
        return "La password deve contenere almeno 8 caratteri."
    if not any(char.isdigit() for char in password):
        return "La password deve contenere almeno un numero."
    if not any(char.isalpha() for char in password):
        return "La password deve contenere almeno una lettera."
    if not any(char in "!@#$%^&*()-_=+[]{}|;:,.<>?/`~" for char in password):
        return "La password deve contenere almeno un carattere speciale (!@#$%^&*()-_=+[]{}|;:,.<>?/`~)."
    return None

# --- Rotta di base ---
@routes.route('/')
def index():
    """
    Home: Rotta principale dell'applicazione.
    """
    return render_template('index.html')


# ------------------ Rotte per gli utenti ------------------
@routes.route('/register', methods=['GET', 'POST'])
def register():
    """
    Registrazione di un nuovo utente.
    """
    token = request.args.get('token')  # Ottiene il token dai parametri della richiesta

    lavoratore = None
    azienda_nome = None
    user_role = 'user'  # Ruolo predefinito per l'utente

    # Se il token esiste, recupera i dati associati
    if token:
        try:
            email = s.loads(token, salt='email-confirmation-salt', max_age=3600)  # Il token è valido per 1 ora
            lavoratore = Lavoratore.query.filter_by(email=email).first()
            azienda_nome = lavoratore.azienda.nome if lavoratore and lavoratore.azienda else None

            # Verifica se l'utente ha già completato la registrazione
            if lavoratore and lavoratore.utente_id:
                flash("Questo utente ha già completato la registrazione.", "info")
                return redirect(url_for('routes.login'))
        except Exception as e:
            current_app.logger.error(f"Error processing token: {e}")
            flash("Il link di registrazione non è valido o è scaduto.", "error")
            return redirect(url_for('routes.login'))

    if request.method == 'POST':
        # Recupera i dati dal modulo
        nome = request.form.get('nome', '').strip() if not lavoratore else lavoratore.nome
        cognome = request.form.get('cognome', '').strip() if not lavoratore else lavoratore.cognome
        email = lavoratore.email if lavoratore else request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        azienda_nome = request.form.get('azienda_nome', '').strip() if not azienda_nome else azienda_nome

        # Controlla che tutti i campi obbligatori siano compilati
        if not all([nome, cognome, email, password, azienda_nome]):
            flash('Tutti i campi sono obbligatori.', 'error')
            return redirect(url_for('routes.register', token=token) if token else url_for('routes.register'))

        # Verifica che l'email sia valida
        if not is_valid_email(email):
            flash('Inserisci un indirizzo email valido.', 'error')
            return redirect(url_for('routes.register', token=token) if token else url_for('routes.register'))

        # Verifica che la password soddisfi i requisiti
        password_error = validate_password(password)
        if password_error:
            flash(password_error, 'error')
            current_app.logger.error(f"Password error: {password_error}")
            return redirect(url_for('routes.register', token=token) if token else url_for('routes.register'))

        try:
            current_app.logger.info(f"Creating user: nome={nome}, email={email}")
            if lavoratore:
                # Registrazione tramite token
                new_user = Utente(
                    nome=nome,
                    email=email,
                    ruolo=user_role,
                    azienda_id=lavoratore.azienda_id,
                    email_confirmed=True
                )
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.flush()

                # Aggiorna utente_id nel lavoratore
                if not lavoratore.utente_id:
                    current_app.logger.info(f"Updating utente_id for lavoratore {lavoratore.id}")
                    lavoratore.utente_id = new_user.id
                    db.session.add(lavoratore)

                db.session.commit()
                current_app.logger.info(f"User {email} successfully registered.")
                flash("Registrazione completata! Ora puoi accedere al sistema.", "success")
                return redirect(url_for('routes.login'))
            
            else:
                # Registrazione senza token
                azienda = Azienda.query.filter_by(nome=azienda_nome).first()
                if not azienda:
                    azienda = Azienda(nome=azienda_nome)
                    db.session.add(azienda)
                    db.session.commit()

                # Il primo utente dell'azienda diventa admin
                user_role = 'admin' if Utente.query.filter_by(azienda_id=azienda.id).count() == 0 else 'user'

                # Genera il token di conferma
                token = s.dumps(email, salt='email-confirmation-salt')

                # Crea un nuovo utente
                new_user = Utente(
                    nome=nome,
                    email=email,
                    ruolo=user_role,
                    azienda_id=azienda.id,
                    email_confirmed=False,
                    confirmation_token=token
                )
                new_user.set_password(password)
                db.session.add(new_user)

                # Aggiunge il lavoratore
                lavoratore = Lavoratore(
                    nome=nome,
                    cognome=cognome,
                    email=email,
                    azienda_id=azienda.id,
                    utente_id=new_user.id
                )
                db.session.add(lavoratore)
                db.session.commit()

                # Invia l'email di conferma
                confirmation_url = url_for('routes.confirm_email', token=token, _external=True)
                invia_email_confirm(email, confirmation_url)

                flash("Registrazione completata! Conferma il tuo indirizzo email.", "success")
                return redirect(url_for('routes.login'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error completing user registration: {e}")
            flash("Si è verificato un errore. Riprova più tardi.", "error")
            return redirect(url_for('routes.register', token=token))

    # Mostra il modulo di registrazione
    return render_template(
        'register.html',
        nome=lavoratore.nome if lavoratore else '',
        cognome=lavoratore.cognome if lavoratore else '',
        email=lavoratore.email if lavoratore else '',
        azienda_nome=azienda_nome,
        token=token
    )


# --- Conferma email ---
@routes.route('/confirm-email/<token>')
def confirm_email(token):
    """
    Conferma l'indirizzo email utilizzando un token.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti

    try:
        email = s.loads(token, salt='email-confirmation-salt', max_age=3600)
        user = Utente.query.filter_by(email=email).first()

        if not user:
            flash('Utente con questo email non trovato.', 'error')
            return redirect(url_for('routes.login'))

        if user.email_confirmed:
            flash('Email già confermata.', 'info')
            return redirect(url_for('routes.login'))

        # Conferma email
        user.email_confirmed = True
        user.confirmation_token = None
        db.session.add(user)

        # Aggiorna utente_id nel lavoratore
        lavoratore = Lavoratore.query.filter_by(email=email).first()
        if lavoratore:
            if not lavoratore.utente_id:
                lavoratore.utente_id = user.id
                db.session.add(lavoratore)
            else:
                current_app.logger.info(f"Lavoratore already linked to user: {lavoratore.utente_id}")
        else:
            current_app.logger.warning(f"Lavoratore with email {email} not found.")

        db.session.commit()
        flash('Email confermata con successo! Ora puoi accedere.', 'success')
        current_app.logger.info(f"Email confirmed: {email}")
    except Exception as e:
        current_app.logger.error(f"Error confirming email: {e}")
        flash('Il token non è valido o è scaduto.', 'error')

    return redirect(url_for('routes.login'))


# --- Reinvia conferma email ---
@routes.route('/resend-confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    """
    Reinvio del link di conferma email.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not is_valid_email(email):
            flash('Inserisci un indirizzo email valido.', 'error')
            return redirect(url_for('routes.resend_confirmation'))

        user = Utente.query.filter_by(email=email).first()

        if user and not user.email_confirmed:
            token = s.dumps(email, salt='email-confirmation-salt')
            confirmation_url = url_for('routes.confirm_email', token=token, _external=True)
            invia_email_confirm(email, confirmation_url)
            flash('Link di conferma inviato al tuo indirizzo email.', 'success')
            current_app.logger.info(f"Resent confirmation link for: {email}")
        else:
            flash('Email già confermata o utente non trovato.', 'error')

    return render_template('resend_confirmation.html')



# --- Accesso al sistema ---
@routes.route('/login', methods=['GET', 'POST'])
def login():
    """Autenticazione utente."""

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if 'resend_confirmation' in request.form:
            # Gestione del pulsante per reinviare la conferma
            user = Utente.query.filter_by(email=email).first()
            if user and not user.email_confirmed:
                token = s.dumps(email, salt='email-confirmation-salt')
                confirmation_url = url_for('routes.confirm_email', token=token, _external=True)
                invia_email_confirm(email, confirmation_url)
                flash('Il link di conferma è stato inviato al tuo indirizzo email.', 'success')
            else:
                flash('L\'email è già confermata oppure l\'utente non esiste.', 'error')
            return redirect(url_for('routes.login'))

        # Gestione del normale login
        password = request.form.get('password', '').strip()
        if not is_valid_email(email):
            flash('Inserisci un email valida.', 'error')
            return redirect(url_for('routes.login'))

        user = Utente.query.filter_by(email=email).first()
        if not user:
            flash('Utente non trovato.', 'error')
            return redirect(url_for('routes.login'))
        
        # Verifica: il dipendente non lavora più
        lavoratore = Lavoratore.query.filter_by(utente_id=user.id).first()
        if lavoratore and lavoratore.data_fine and lavoratore.data_fine < datetime.utcnow().date():
            flash('Accesso negato. La tua relazione lavorativa è terminata.', 'error')
            return redirect(url_for('routes.login'))

        # Verifica: email non confermata
        if not user.email_confirmed and user.ruolo != "superuser":
            flash('Conferma il tuo indirizzo email prima di accedere.', 'error')
            return redirect(url_for('routes.login'))

        # Verifica: password non corretta
        if not user.check_password(password):
            flash('Password non corretta.', 'error')
            return redirect(url_for('routes.login'))

        login_user(user)
        flash('Accesso effettuato con successo.', 'success')
        return redirect(url_for('routes.index'))
    
    return render_template('login.html')



# --- Logout dal sistema ---
@routes.route('/logout')
@login_required
def logout():
    """
    Disconnessione dell'utente.
    """
    if hasattr(current_user, 'email'):
        current_app.logger.info(f"User logged out: {current_user.email}")
    else:
        current_app.logger.info("Anonymous user logged out.")
    
    logout_user()
    session.pop('_flashes', None)  # Rimozione dei messaggi flash dalla sessione
    return redirect(url_for('routes.index'))



# ------------------ Rotte personali per utenti ------------------

@routes.route('/profile')
@login_required
def profile():
    """
    Mostra il profilo dell'utente corrente.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti
    try:
        # Dati dell'utente corrente
        user_data = {
            'nome': current_user.nome,
            'email': current_user.email,
            'azienda': current_user.azienda.nome if current_user.azienda else None,
            'data_creazione': current_user.data_creazione,
        }
        return render_template('profile.html', user_data=user_data)
    except Exception as e:
        current_app.logger.error(f"Error displaying user profile: {e}")
        flash("Errore durante la visualizzazione del profilo.", 'error')
        return redirect(url_for('routes.index'))


@routes.route('/update-password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_password(user_id):
    """
    Aggiorna la password dell'utente.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti
    user = Utente.query.get(user_id)
    if not user:
        flash("Utente non trovato.", "error")
        return redirect(url_for('routes.list_items', model="utenti"))

    if request.method == 'POST':
        # Ottieni la nuova password dal modulo
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Validazione delle password
        if new_password != confirm_password:
            flash("Le password non corrispondono.", "error")
            return redirect(url_for('routes.update_password', user_id=user_id))

        if not validate_password(new_password):
            flash("La password deve avere almeno 8 caratteri, includere lettere e numeri.", "error")
            return redirect(url_for('routes.update_password', user_id=user_id))

        # Imposta la nuova password
        user.set_password(new_password)
        try:
            db.session.commit()
            flash("Password aggiornata con successo.", "success")
            return redirect(url_for('routes.profile'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating password: {e}")
            flash("Errore durante l'aggiornamento della password. Riprova più tardi.", "error")
            return redirect(url_for('routes.update_password', user_id=user_id))

    return render_template('update_password.html', user=user)


# ------------------ Rotte per il reset della Password ------------------

@routes.route('/password-dimenticata', methods=['GET', 'POST'])
def password_dimenticata():
    """
    Percorso per richiedere il reset della password.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti

    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        # Validazione dell'email
        if not email or '@' not in email:
            flash("Inserisci un'email valida.", 'error')
            return redirect(url_for('routes.password_dimenticata'))

        user = Utente.query.filter_by(email=email).first()
        if user:
            try:
                # Creazione del token per il reset della password
                token = s.dumps(email, salt='password-reset-salt')
                reset_url = url_for('routes.reset_password', token=token, _external=True)
                
                # Invio dell'email di reset
                invia_email_reset(user.email, reset_url)
                flash("Le istruzioni per il reset della password sono state inviate al tuo indirizzo email.", 'success')
                current_app.logger.info(f"Password reset link sent to: {email}")
            except Exception as e:
                current_app.logger.error(f"Error sending password reset email: {e}")
                flash("Errore durante l'invio dell'email. Riprova più tardi.", 'error')
        else:
            flash("Nessun utente trovato con questo indirizzo email.", 'error')

    return render_template('password_dimenticata.html')


@routes.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Percorso per resettare la password utilizzando un token.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti

    try:
        # Decodifica il token e verifica la validità
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception as e:
        current_app.logger.error(f"Error decoding token: {e}")
        flash("Il link per il reset della password non è valido o è scaduto.", 'error')
        return redirect(url_for('routes.password_dimenticata'))

    if request.method == 'POST':
        nuova_password = request.form.get('password', '').strip()

        # Validazione della password
        password_error = validate_password(nuova_password)
        if password_error:
            flash(password_error, 'error')
            return redirect(url_for('routes.reset_password', token=token))

        user = Utente.query.filter_by(email=email).first()
        if user:
            try:
                # Aggiorna la password dell'utente
                user.set_password(nuova_password)
                db.session.commit()

                flash("Password aggiornata con successo.", 'success')
                current_app.logger.info(f"Password updated for user: {email}")

                # Rimuove la password dalla memoria
                del nuova_password

                return redirect(url_for('routes.login'))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error updating password: {e}")
                flash("Errore durante l'aggiornamento della password. Riprova più tardi.", 'error')
        else:
            flash("Utente non trovato.", 'error')
            return redirect(url_for('routes.password_dimenticata'))

    return render_template('reset_password.html', token=token)


def invia_email_reset(email, reset_url):
    """
    Invia un'email con il link per il reset della password.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti
    try:
        msg = Message(
            subject='Reset della Password',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = (
            f"Per resettare la tua password, visita il seguente link:\n{reset_url}\n\n"
            f"Se non hai richiesto il reset della password, ignora questa email."
        )
        mail.send(msg)
        current_app.logger.info(f"Email sent successfully to: {email}")
    except smtplib.SMTPAuthenticationError:
        current_app.logger.error("SMTP authentication error. Check email server credentials.")
        raise
    except smtplib.SMTPException as e:
        current_app.logger.error(f"SMTP error while sending email: {e}")
        raise
    except Exception as e:
        current_app.logger.error(f"General error while sending email: {e}")
        raise



# ------------------ Rotte dinamiche CRUD ------------------
@routes.route('/<model>', methods=['GET'])
@login_required
def list_items(model):
    """
    Lista: Mostra l'elenco di tutti gli elementi del modello specificato con verifica dei permessi per ogni azione.
    """

    session.pop('_flashes', None)

    if model not in MODELS:
        logger.error(f"Model {model} not found")
        abort(404, description="Modello non trovato.")

    model_class = MODELS[model]

    # Verifica dei permessi per visualizzare il modello
    if not has_access_to_model(model, action='view'):
        logger.warning(f"Access denied to model {model} for user {current_user.id}")
        abort(403)

    # Verifica dei permessi per creare una nuova voce
    can_create = has_access_to_model(model, action='create')

    # Query di base alla tabella
    query = model_class.query

    # Filtraggio per il modello `lavoratori`
    if model == 'lavoratori':
        today = datetime.utcnow().date()
        # Gli amministratori vedono tutti i lavoratori, indipendentemente dalla data di fine
        if current_user.ruolo == 'admin':
            query = query.filter_by(azienda_id=current_user.azienda_id)
        else:
            # Gli altri ruoli vedono solo i lavoratori attivi
            query = query.filter(
                (model_class.data_fine.is_(None)) | (model_class.data_fine >= today)
            )

    # Filtraggio per il modello `spese`
    if model == 'spese' and current_user.ruolo == 'user':
        query = query.filter_by(owner=current_user.id)

    # Paginazione
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = query.order_by(model_class.id.asc()).paginate(page=page, per_page=per_page)

    # Logging
    logger.info(f"Model: {model}, User: {current_user.id}, Number of records: {len(pagination.items)}")

    # Creazione dell'elenco delle colonne
    columns = [column.name for column in model_class.__table__.columns]

    # Limitazione delle colonne visibili
    if current_user.ruolo != 'superuser':
        visible_columns = [col for col in columns if col not in ['id', 'utente_id', 'password_hash', 'owner']]
    else:
        visible_columns = [col for col in columns if col != 'password_hash']

    # Creazione dei dati per la visualizzazione
    items = []
    for item in pagination.items:
        item_dict = {}

        # Conversione degli attributi del record in un dizionario
        for column in columns:
            value = getattr(item, column)

            # Gestione dei campi con relazioni esterne
            if column == 'azienda_id':
                azienda = Azienda.query.get(value)
                value = azienda.nome if azienda else 'Non specificato'
            elif column == 'id_lavoratore':
                lavoratore = Lavoratore.query.get(value)
                value = f"{lavoratore.nome} {lavoratore.cognome}" if lavoratore else 'Non specificato'
            elif column == 'id_supervisore':
                supervisore = Lavoratore.query.get(value)
                value = f"{supervisore.nome} {supervisore.cognome}" if supervisore else 'Non specificato'
            elif column == 'id_categoria':
                categoria = CategoriaSpesa.query.get(value)
                value = categoria.nome_categoria if categoria else 'Non specificato'

            # Formattazione delle date
            if isinstance(value, (datetime, date)):
                value = value.strftime('%d-%m-%Y')

            item_dict[column] = value

        # Generazione degli URL per le operazioni
        item_dict['view_url'] = url_for('routes.retrieve_item', model=model, item_id=item.id)
        item_dict['edit_url'] = url_for('routes.update_item', model=model, item_id=item.id)
        item_dict['delete_url'] = url_for('routes.delete_item', model=model, item_id=item.id)

        # Verifica dei permessi per modificare ed eliminare
        try:
            item_dict['can_edit'] = has_access_to_model(model, item=item, action='edit')
        except:
            item_dict['can_edit'] = False

        try:
            item_dict['can_delete'] = has_access_to_model(model, item=item, action='delete')
        except:
            item_dict['can_delete'] = False

        items.append(item_dict)

    return render_template(
        'dynamic_list.html',
        model=model,
        items=items,
        columns=visible_columns,  # Passa solo le colonne visibili
        pagination=pagination,
        getattr=getattr,
        get_meta=get_meta,
        can_create=can_create
    )


@routes.route('/<model>/new', methods=['GET', 'POST'])
@login_required
def create_item(model):
    """
    Create: Aggiunge un nuovo elemento al modello specificato.
    """
    session.pop('_flashes', None)

    if model not in MODELS:
        abort(404, description="Modello non trovato.")

    model_class = MODELS[model]

    # Controllo accesso per l'azione di creazione
    has_access_to_model(model, action='create')

    if request.method == 'POST':
        try:
            data = request.form.to_dict()

            # Aggiunge automaticamente l'utente corrente come proprietario (se esiste il campo `owner`)
            if hasattr(model_class, 'owner'):
                data['owner'] = current_user.id

            # Imposta azienda_id per gli utenti non superuser
            if hasattr(model_class, 'azienda_id') and current_user.ruolo != 'superuser':
                data['azienda_id'] = current_user.azienda_id

            # Converte stringhe vuote in None per tutti i dati
            for key, value in data.items():
                if value == '':
                    data[key] = None
                
            # Gestione del file immagine_ricevuta
            if 'immagine_ricevuta' in request.files:
                file = request.files['immagine_ricevuta']
                if file and allowed_file(file.filename):
                    upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
                    file_path = save_uploaded_file(file, upload_folder)
                    data['immagine_ricevuta'] = file_path  # Aggiunge il percorso del file ai dati

            # Gestione del modello `lavoratori`
            if model == "lavoratori":
                # Controlla se l'email esiste già
                email = data.get('email')
                if not email:
                    flash(f"L'email è obbligatoria per la creazione di un lavoratore.", 'error')
                    raise ValueError("L'email è obbligatoria per la creazione di un lavoratore.")
                
                existing_user = Utente.query.filter_by(email=email).first()

                if existing_user:
                    # Se l'utente esiste, lo associa al lavoratore
                    data['utente_id'] = existing_user.id
                else:
                    # Genera un token per il nuovo utente
                    token = s.dumps(email, salt='email-confirmation-salt')

                    # Invia un'email per completare la registrazione
                    registration_url = url_for('routes.register', token=token, _external=True)
                    invia_email_registrazione(email, registration_url)

                    # Lascialo `utente_id` vuoto (None) fino al completamento della registrazione
                    data['utente_id'] = None

            # Trasforma i dati per il modello e crea un oggetto
            transformed_data = transform_data(data, model_class)
            new_item = model_class(**transformed_data)
            db.session.add(new_item)
            db.session.commit()

            flash(f"{model.capitalize()} creato con successo.", 'success')
            return redirect(url_for('routes.retrieve_item', model=model, item_id=new_item.id))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Errore durante la creazione di {model}: {e}")

    # Genera l'elenco delle colonne per il modulo (esclude 'password_hash' e 'utente_id')
    columns = [
        {
            'name': column.name,
            'type': column.type.__class__.__name__
        }
        for column in model_class.__table__.columns 
        if column.name not in ['password_hash', 'utente_id', 'owner']  # Esclude password_hash, owner e utente_id
    ]

    # Ottiene tutti i dati necessari per i menu a tendina
    aziende = Azienda.query.all()
    lavoratori = Lavoratore.query.filter_by(azienda_id=current_user.azienda_id).all()  # Solo i dipendenti dell'azienda corrente
    categorie = CategoriaSpesa.query.all()  # Tutte le categorie
    supervisori = Lavoratore.query.filter_by(azienda_id=current_user.azienda_id).all()  # Tutti i dipendenti come supervisori

    return render_template(
        'dynamic_form.html',
        model=model,
        columns=columns,
        aziende=aziende,
        lavoratori=lavoratori,
        categorie=categorie,
        supervisori=supervisori,
        action="creare",
        VALUTE=VALUTE,
        STATI=STATI,
        METODI_PAGAMENTO=METODI_PAGAMENTO
    )



@routes.route('/<model>/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def update_item(model, item_id):
    """
    Update: Modifica un elemento esistente del modello specificato.
    """
    session.pop('_flashes', None)

    if model not in MODELS:
        abort(404, description="Modello non trovato.")

    model_class = MODELS[model]
    item = model_class.query.get_or_404(item_id)

    # Controllo accesso con indicazione dell'azione
    has_access_to_model(model, item=item, action='edit')

    if request.method == 'POST':
        try:
            data = request.form.to_dict()

            # Controllo unicità email se il modello è Utente
            if model == "utenti" and "email" in data:
                email = data["email"]
                if not isinstance(email, str) or not is_valid_email(email.strip()):
                    flash("Email non valido.", "error")
                    return redirect(url_for('routes.update_item', model=model, item_id=item_id))
                existing_user = Utente.query.filter_by(email=email.strip()).first()
                if existing_user and existing_user.id != item_id:
                    flash("Questo email è già registrato.", "error")
                    return redirect(url_for('routes.update_item', model=model, item_id=item_id))
                data["email"] = email.strip()

            # Aggiornamento azienda_id solo per i superuser
            if current_user.ruolo != 'superuser' and 'azienda_id' in data:
                data.pop('azienda_id')

            # Converte stringhe vuote in None per tutti i dati
            for key, value in data.items():
                if value == '':
                    data[key] = None

            if model == 'lavoratori' and item.utente_id:
                utente = Utente.query.get(item.utente_id)
                if utente:
                    utente.nome = data.get('nome', utente.nome)
                    utente.email = data.get('email', utente.email)
                    db.session.add(utente)

            # Gestione del file immagine_ricevuta
            if 'immagine_ricevuta' in request.files:
                file = request.files['immagine_ricevuta']
                if file and allowed_file(file.filename):
                    upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
                    file_path = save_uploaded_file(file, upload_folder)
                    data['immagine_ricevuta'] = file_path
                elif file and not allowed_file(file.filename):
                    flash("Formato del file non consentito. Carica un file valido.", "error")
                    return redirect(url_for('routes.update_item', model=model, item_id=item_id))

            # Trasforma i dati per il modello e aggiorna l'oggetto
            transformed_data = transform_data(data, model_class)
            for key, value in transformed_data.items():
                setattr(item, key, value)

            db.session.commit()
            flash(f"{model.capitalize()} aggiornato con successo.", 'success')
            return redirect(url_for('routes.retrieve_item', model=model, item_id=item.id))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Errore durante l'aggiornamento del modello {model} con ID {item_id}: {e}")

    # Trasforma l'oggetto `item` in un dizionario per il template
    record = {
        column.name: getattr(item, column.name, None)
        for column in model_class.__table__.columns
    }

    # Genera l'elenco delle colonne con il tipo di dati
    columns = [
        {
            'name': column.name,
            'type': column.type.__class__.__name__
        }
        for column in model_class.__table__.columns if column.name not in ['password_hash', 'owner']
    ]

    # Prepara i dati per i menu a tendina
    aziende = Azienda.query.all()
    lavoratori = Lavoratore.query.filter_by(azienda_id=current_user.azienda_id).all()
    categorie = CategoriaSpesa.query.all()
    supervisori = Lavoratore.query.filter_by(azienda_id=current_user.azienda_id).all()

    return render_template(
        'dynamic_form.html',
        model=model,
        item=record,
        columns=columns,
        action="modificare",
        aziende=aziende,
        lavoratori=lavoratori,
        categorie=categorie,
        supervisori=supervisori,
        VALUTE=VALUTE,
        STATI=STATI,
        METODI_PAGAMENTO=METODI_PAGAMENTO
    )



@routes.route('/<model>/<int:item_id>', methods=['GET'])
@login_required
def retrieve_item(model, item_id):
    """
    Retrieve: Mostra i dettagli di un elemento specifico del modello.
    """
    session.pop('_flashes', None)  # Rimuove i messaggi flash precedenti

    if model not in MODELS:
        abort(404, description="Modello non trovato.")

    model_class = MODELS[model]
    item = model_class.query.get_or_404(item_id)
    logger.info(f"Elemento recuperato: {item}")

    # Controllo accesso utilizzando has_access_to_model
    has_access_to_model(model, item=item, action='detail')

    # Crea un dizionario dei dettagli dell'elemento
    record = {}
    for column in model_class.__table__.columns:
        column_name = column.name

        # Salta la colonna della password
        if column_name == "password_hash":
            continue

        # Nasconde 'id', 'utente_id' e 'owner' per gli utenti non superuser
        if column_name in ["id", "utente_id", "owner"] and current_user.ruolo not in ["superuser"]:
            continue

        # Converte 'azienda_id' nel nome dell'azienda
        if column_name == "azienda_id" and hasattr(item, "azienda") and item.azienda:
            record["azienda"] = item.azienda.nome
            continue

        # Converte gli ID nei rispettivi valori
        if column_name in ["id_lavoratore", "id_supervisore", "id_categoria"]:
            related_model = {
                "id_lavoratore": Lavoratore,
                "id_supervisore": Lavoratore,
                "id_categoria": CategoriaSpesa,
            }.get(column_name)

            related_instance = related_model.query.get(getattr(item, column_name))
            if related_instance:
                record[column_name.replace("id_", "")] = (
                    f"{related_instance.nome} {related_instance.cognome}"
                    if hasattr(related_instance, "nome")
                    else related_instance.nome_categoria
                )
            else:
                record[column_name.replace("id_", "")] = "Non specificato"
            continue

        # Converte le date in un formato leggibile
        if isinstance(getattr(item, column_name), (datetime, date)):
            record[column_name] = getattr(item, column_name).strftime("%d-%m-%Y")
        else:
            record[column_name] = getattr(item, column_name, None)

    # Aggiunge pulsanti per la modifica e l'eliminazione, se l'utente ha i permessi
    can_edit = has_access_to_model(model, item=item, action="edit") or False
    can_delete = has_access_to_model(model, item=item, action="delete") or False

    return render_template(
        'dynamic_detail.html',
        model_name=model,
        record=record,
        can_edit=can_edit,
        can_delete=can_delete,
        edit_url=url_for('routes.update_item', model=model, item_id=item.id) if can_edit else None,
        delete_url=url_for('routes.delete_item', model=model, item_id=item.id) if can_delete else None
    )


@routes.route('/<model>/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_item(model, item_id):
    """
    Delete: Elimina un elemento dal modello specificato.
    """
    session.pop('_flashes', None)

    if model not in MODELS:
        abort(404, description="Modello non trovato.")

    model_class = MODELS[model]
    item = model_class.query.get_or_404(item_id)

    # Controllo accesso utilizzando la funzione has_access_to_model
    has_access_to_model(model, item=item, action='delete')

    try:
        db.session.delete(item)
        db.session.commit()
        current_app.logger.info(f"{model.capitalize()} con ID {item_id} eliminato con successo.")
        flash(f"{model.capitalize()} eliminato con successo.", 'success')
        return redirect(url_for('routes.list_items', model=model))
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Errore durante l'eliminazione: {e}")
        flash("Errore durante l'eliminazione. Riprova più tardi.", 'error')
        return redirect(url_for('routes.list_items', model=model))

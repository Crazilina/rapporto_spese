from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.dialects.postgresql import ENUM
from flask_login import UserMixin
from sqlalchemy_utils import EmailType
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# Enumerazioni per valori predefiniti
VALUTE = ('EUR', 'USD', 'RUB')  # Valute accettate
STATI = ("Richiesta di Rimborso", "Pagato", "Approvato", "Rimborsato")  # Stati delle spese
METODI_PAGAMENTO = ('Carta aziendale', 'Carta personale', 'Contanti', 'Bonifico')  # Metodi di pagamento
RUOLI = ('user', 'admin', 'superuser')  # Ruoli definiti


# Modello Azienda
class Azienda(db.Model):
    __tablename__ = 'aziende'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, unique=True, index=True)
    data_creazione = db.Column(db.DateTime, default=datetime.utcnow)
    utenti = db.relationship('Utente', backref='azienda', lazy=True)

    class Meta:
        singular = "Azienda"
        plural = "Aziende"
        gender = "femminile"

    def __repr__(self):
        return f"<Azienda {self.nome}>"

# Modello Utente
class Utente(UserMixin, db.Model):
    """
    Modello per rappresentare un utente.
    """
    __tablename__ = 'utenti'
    id = db.Column(db.Integer, primary_key=True)  # Identificatore univoco per l'utente
    nome = db.Column(db.String(100), nullable=False)  # Nome dell'utente
    email = db.Column(EmailType, unique=True, nullable=False)  # Email univoca dell'utente
    password_hash = db.Column(db.Text, nullable=True)  # Password crittografata dell'utente
    ruolo = db.Column(db.String(10), default='user')  # Ruolo dell'utente ('user', 'admin', 'superuser')
    azienda_id = db.Column(db.Integer, db.ForeignKey('aziende.id'), index=True)  # Collegamento all'azienda
    email_confirmed = db.Column(db.Boolean, default=False)  # Indica se l'email è stata confermata
    confirmation_token = db.Column(db.String(256), unique=True, nullable=True)  # Token di conferma

    data_creazione = db.Column(db.DateTime, default=datetime.utcnow)  # Data di creazione dell'utente
    data_modifica = db.Column(db.DateTime, onupdate=datetime.utcnow)  # Data di ultima modifica dell'utente

    def set_password(self, password):
        """Metodo per impostare una password crittografata."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Metodo per verificare la password crittografata."""
        return check_password_hash(self.password_hash, password)
    

    @staticmethod
    def get_user_info(user_id):
        """Metodo statico per ottenere le informazioni di un utente."""
        utente = Utente.query.get(user_id)
        if utente:
            return {
                'nome': utente.nome,
                'email': utente.email,
                'ruolo': utente.ruolo,
                'azienda': utente.azienda.nome if utente.azienda else None
            }
        return None

    @db.validates('ruolo')
    def validate_role(self, key, value):
        """Valida che un superuser non sia associato a un'azienda."""
        if value == 'superuser' and self.azienda_id is not None:
            raise ValueError("Un superuser non può essere associato a un'azienda.")
        return value

    class Meta:
        singular = "Utente"
        plural = "Utenti"
        gender = "maschile"

    def __repr__(self):
        return f"<Utente {self.nome} - {self.ruolo}>"

# Modello Lavoratore
class Lavoratore(db.Model):
    """
    Modello per rappresentare un lavoratore.
    """
    __tablename__ = 'lavoratori'
    id = db.Column(db.Integer, primary_key=True)  # Identificatore univoco per il lavoratore
    nome = db.Column(db.String(100), nullable=False, index=True)  # Nome del lavoratore
    cognome = db.Column(db.String(100), nullable=False, index=True)  # Cognome del lavoratore
    data_di_nascita = db.Column(db.Date, nullable=True)  # Data di nascita
    email = db.Column(EmailType, unique=True, nullable=False)  # Email unica del lavoratore
    posizione = db.Column(db.String(100), nullable=True)  # Posizione del lavoratore
    dipartimento = db.Column(db.String(100), nullable=True)  # Dipartimento
    azienda_id = db.Column(db.Integer, db.ForeignKey('aziende.id'), nullable=False)  # Collegamento all'azienda
    utente_id = db.Column(db.Integer, db.ForeignKey('utenti.id'), nullable=True)
    data_inizio = db.Column(db.Date, nullable=False, default=datetime.utcnow)  # Дата начала работы
    data_fine = db.Column(db.Date, nullable=True)  # Дата окончания работы
    is_active = db.Column(db.Boolean, nullable=False, default=True)  # Активен ли сотрудник

    azienda = db.relationship('Azienda', backref=db.backref('lavoratori', lazy=True))  # Relazione con l'azienda
    utente = db.relationship('Utente', backref=db.backref('lavoratori', lazy=True))  # Relazione con l'utente

    class Meta:
        singular = "Lavoratore"
        plural = "Lavoratori"
        gender = "maschile"
        
    @property
    def is_active(self):
        """Определяет активность сотрудника."""
        if self.data_fine:
            return self.data_fine >= datetime.utcnow().date()
        return True

    def __repr__(self):
        return f"<Lavoratore {self.nome} {self.cognome}>"

# Modello CategoriaSpesa
class CategoriaSpesa(db.Model):
    """
    Modello per rappresentare una categoria di spese.
    """
    __tablename__ = 'categorie_spese'
    id = db.Column(db.Integer, primary_key=True)  # Identificatore univoco
    nome_categoria = db.Column(db.String(100), nullable=False, unique=True)  # Nome della categoria
    descrizione = db.Column(db.Text, nullable=True)  # Descrizione della categoria
    owner = db.Column(db.Integer, db.ForeignKey('utenti.id'), nullable=False)

    class Meta:
        singular = "Categoria Spesa"
        plural = "Categorie Spese"
        gender = "femminile"

    def __repr__(self):
        return f"<Categoria spesa {self.nome_categoria}>"

# Modello Spesa
class Spesa(db.Model):
    """
    Modello per rappresentare una spesa.
    """
    __tablename__ = 'spese'

    id = db.Column(db.Integer, primary_key=True)  # Identificatore univoco per la spesa
    id_lavoratore = db.Column(db.Integer, db.ForeignKey('lavoratori.id'), nullable=False)  # Collegamento al lavoratore
    id_supervisore = db.Column(db.Integer, db.ForeignKey('lavoratori.id'), nullable=False)  # Collegamento al supervisore
    id_categoria = db.Column(db.Integer, db.ForeignKey('categorie_spese.id'), nullable=False)  # Collegamento alla categoria
    
    owner = db.Column(db.Integer, db.ForeignKey('utenti.id'), nullable=False)
    
    lavoratore_rel = db.relationship(
        'Lavoratore',
        backref=db.backref('spese', lazy=True),
        foreign_keys=[id_lavoratore]
    )  # Relazione con il lavoratore

    supervisore_rel = db.relationship(
        'Lavoratore',
        foreign_keys=[id_supervisore],
        backref=db.backref('spese_supervisionate', lazy=True)
    )  # Relazione con il supervisore

    categoria_rel = db.relationship(
        'CategoriaSpesa',
        backref=db.backref('spese', lazy=True)
    )  # Relazione con la categoria

    data_spese = db.Column(db.Date, nullable=False, default=datetime.utcnow)  # Data della spesa
    totale_importo = db.Column(db.Numeric(10, 2), nullable=False)  # Importo totale
    valuta = db.Column(ENUM(*VALUTE, name="valuta_enum"), nullable=False, default="EUR")  # Valuta
    descrizione = db.Column(db.Text, nullable=True)  # Descrizione della spesa
    stato = db.Column(ENUM(*STATI, name="stato_enum"), default="Richiesta di Rimborso")  # Stato della spesa
    immagine_ricevuta = db.Column(db.String(255), nullable=True)  # Ricevuta
    data_creazione = db.Column(db.DateTime, default=datetime.utcnow)  # Data di creazione
    data_modifica = db.Column(db.DateTime, onupdate=datetime.utcnow)  # Data di modifica
    metodo_pagamento = db.Column(ENUM(*METODI_PAGAMENTO, name="pagamento_enum"), nullable=False, default="Carta aziendale")  # Metodo di pagamento

    @db.validates('totale_importo')
    def validate_totale_importo(self, key, value):
        """Valida che il totale importo sia maggiore di 0."""
        if value <= 0:
            raise ValueError("Il totale importo deve essere maggiore di 0.")
        return value
    
    class Meta:
        singular = "Spesa"
        plural = "Spese"
        gender = "femminile"

    def __repr__(self):
        return f"<Spesa {self.id} - {self.totale_importo} EUR>"

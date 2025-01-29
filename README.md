# Gestione Spese

**Gestione Spese** è un'applicazione web sviluppata con Python/Flask per gestire dipendenti, spese aziendali e altri dati aziendali.

## 🛠 Tecnologie utilizzate
- Python 3.9+
- Flask
- SQLAlchemy
- PostgreSQL
- HTML/CSS

---
## ⚙️ Installazione e avvio locale

### 1. Clona il repository
Clona il progetto da GitHub:
```bash
git clone https://github.com/Crazilina/rapporto_spese
cd rapporto_spese
```

### 2. Crea un ambiente virtuale
Crea e attiva un ambiente virtuale:

```bash
python3 -m venv env
source env/bin/activate  # Su Windows: env\Scripts\activate
```

### 3. Installa le dipendenze

Installa le librerie richieste dal file requirements.txt:

```bash
pip install -r requirements.txt
```

### 4. Configura le variabili di ambiente

Crea un file configuration.ini nella directory principale e aggiungi le seguenti variabili:

```
[postgresql]
host=localhost                # Host del database PostgreSQL
database=nome_database         # Nome del database
user=nome_utente_database      # Nome utente del database
password=tuo_password_database # Password del database
port=5432                      # Porta predefinita per PostgreSQL

[mail]
EMAIL_HOST = smtp.gmail.com            # Host del server email
EMAIL_PORT = 587                       # Porta SMTP per TLS
EMAIL_HOST_USER = tuo_email@gmail.com  # Inserisci il tuo indirizzo email
EMAIL_HOST_PASSWORD = tua_password     # App-specific password
EMAIL_USE_TLS = True                   # Abilita TLS
EMAIL_USE_SSL = False                  # Disabilita SSL (non necessario con TLS)

[app]
SECRET_KEY = tua_chiave_segreta        # Una chiave segreta per la sicurezza dell'app
```

### 5. Creazione del database
1. Crea un nuovo database PostgreSQL

Esegui il seguente comando per creare il database:

```bash
psql -U nome_utente_database
tuo_password_database
```
E nel SQL:
```sql
CREATE DATABASE nome_database;
\q
```

2. Inizializza le migrazioni del database

Dopo aver configurato le variabili di ambiente, esegui i seguenti comandi per impostare il database:

```bash
flask db init
flask db migrate -m "Migrazione iniziale"
flask db upgrade
```
Durante la migrazione, potrebbe essere necessario aggiungere questa riga in alto ai file generati nella cartella migrations/versions/:

```bash
import sqlalchemy_utils
```

3. Crea un superuser

Dopo aver configurato il database, crea un utente amministratore per accedere al sistema:

```bash
flask create-superuser
```

### 6. Avvia l'applicazione
Esegui l'applicazione:

```bash
flask run
```
oppure
```bash
python3 app.py
```

L'app sarà disponibile all'indirizzo: http://127.0.0.1:5000
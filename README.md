# Guardrail

Guardrail è un plugin per DevStack che estende OpenStack con un sistema automatizzato di verifica della conformità delle istanze gestite da Nova.

Il servizio esegue scansioni periodiche o manuali, confronta le caratteristiche delle VM con le policy definite dall’amministratore e registra le violazioni in un database SQLite. I risultati sono consultabili attraverso un’API REST e una dashboard web.

Guardrail utilizza Nova per recuperare le informazioni sulle istanze, Neutron per le operazioni di quarantena e Keystone per l’autenticazione e l’autorizzazione.

## Funzionalità principali

- Scansione periodica automatizzata delle istanze Nova.
- Avvio manuale delle scansioni tramite API.
- Verifica di otto regole di conformità.
- Configurazione centralizzata delle policy.
- Gestione dei limiti globali e specifici per progetto.
- Registrazione dello storico delle scansioni e delle violazioni.
- Quarantena automatica configurabile.
- Ripristino manuale della configurazione di rete.
- API REST e dashboard web.
- Autenticazione e autorizzazione tramite Keystone.
- Registrazione delle operazioni amministrative.

## Regole di conformità

| Regola | Descrizione |
|---|---|
| R1 | Verifica la presenza e il formato corretto del metadato owner. |
| R2 | Verifica che la RAM assegnata alla singola VM non superi il limite configurato. |
| R3 | Verifica che il numero di vCPU assegnate alla singola VM non superi il limite configurato. |
| R4 | Verifica che l’immagine utilizzata dalla VM appartenga alla lista delle immagini autorizzate. |
| R5 | Verifica che il nome della VM rispetti il pattern e la lunghezza massima configurati. |
| R6 | Verifica che il metadato security_profile sia presente e abbia un valore ammesso. |
| R7 | Rileva le VM che permangono nello stato ERROR per il numero di scansioni consecutive configurato. |
| R8 | Verifica che il consumo aggregato di RAM e vCPU del progetto non superi le soglie configurate. |

Per R6 sono ammessi i profili web, database e general.

R2 e R3 supportano limiti specifici per progetto, con utilizzo dei limiti globali quando non è presente una configurazione dedicata. R8 controlla i consumi aggregati del progetto.

## Quarantena

La configurazione predefinita abilita la quarantena automatica esclusivamente per R4 e R6:

- R4: utilizzo di un’immagine non autorizzata.
- R6: profilo di sicurezza mancante o non valido.

Le altre regole generano violazioni senza attivare automaticamente la quarantena.

La configurazione predefinita imposta:

    "quarantine_dry_run": true

In questa modalità le operazioni di quarantena sono simulate: gli eventi vengono registrati, ma il security group non viene realmente applicato alle porte Neutron.

Il ripristino della configurazione di rete è un’operazione manuale riservata agli amministratori.

## Architettura

| Componente | Responsabilità |
|---|---|
| guardrail/controller.py | Coordina le scansioni, applica le policy e gestisce le violazioni. |
| guardrail/rules.py | Implementa i controlli di conformità sulle singole istanze. |
| guardrail/quarantine.py | Gestisce le operazioni di quarantena e ripristino tramite Neutron. |
| guardrail/database.py | Gestisce la persistenza SQLite di scansioni, violazioni ed eventi. |
| guardrail/api.py | Espone le API REST e la dashboard web. |
| guardrail/scheduler.py | Esegue le scansioni periodiche. |
| devstack/plugin.sh | Gestisce installazione, configurazione, avvio e arresto del plugin DevStack. |
| devstack/settings | Definisce le impostazioni e i servizi del plugin. |
| etc/config.json | Contiene la configurazione predefinita delle policy. |
| tests/ | Contiene i test automatici del progetto. |

R8 è gestita dal controller attraverso il calcolo dei consumi aggregati per progetto.

## Requisiti

- Ubuntu con DevStack installato e funzionante.
- OpenStack con i servizi Nova, Neutron e Keystone.
- Python 3.
- Ambiente Python DevStack contenente le dipendenze richieste.

Le dipendenze Python sono dichiarate in requirements.txt:

- Flask
- openstacksdk
- keystonemiddleware

Il plugin verifica la disponibilità delle dipendenze nell’ambiente Python condiviso da DevStack.

## Installazione in DevStack

Clonare il repository:

    cd /opt/stack
    git clone https://github.com/Armando9889/Guardrail.git guardrail

Aggiungere la seguente configurazione al file local.conf di DevStack:

    enable_plugin guardrail https://github.com/Armando9889/Guardrail.git main

Eseguire DevStack secondo la normale procedura di installazione.

Durante la configurazione il plugin:

1. Verifica la disponibilità dell ambiente Python e delle dipendenze.
2. Crea le directory necessarie per configurazione, log e database.
3. Copia la configurazione predefinita se non esiste già una configurazione runtime.
4. Inizializza il database SQLite.
5. Avvia i processi API e scheduler.

I processi vengono gestiti attraverso il sistema di gestione dei servizi di DevStack.

## Configurazione

Il file di configurazione predefinito si trova in:

    etc/config.json

Durante l installazione viene copiato in:

    /etc/guardrail/config.json

Un file di configurazione runtime già esistente viene preservato.

I principali parametri disponibili sono:

| Parametro | Valore predefinito | Descrizione |
|---|---:|---|
| scan_interval_seconds | 300 | Intervallo tra le scansioni automatiche, in secondi. |
| max_ram_mb | 4096 | Limite RAM per singola VM, in MB. |
| max_vcpus | 2 | Limite vCPU per singola VM. |
| allowed_image_ids | [] | Identificativi delle immagini autorizzate. |
| name_pattern | Espressione regolare | Pattern ammesso per il nome delle VM. |
| max_name_length | 50 | Lunghezza massima del nome della VM. |
| error_scan_threshold | 3 | Numero di scansioni consecutive in stato ERROR. |
| max_project_ram_mb | 8192 | Limite RAM aggregato per progetto, in MB. |
| max_project_vcpus | 8 | Limite vCPU aggregato per progetto. |
| auto_quarantine_rules | [R4, R6] | Regole abilitate alla quarantena automatica. |
| quarantine_security_group | guardrail-quarantine | Security group utilizzato per la quarantena. |
| quarantine_dry_run | true | Abilita la simulazione delle operazioni di quarantena. |
| project_limits | {} | Limiti specifici per progetto. |

### Immagini autorizzate

Il parametro allowed_image_ids contiene gli identificativi delle immagini OpenStack autorizzate.

Esempio:

    allowed_image_ids = [identificativo-immagine-autorizzata]

Quando la lista è vuota, il controllo R4 non genera violazioni. Per attivare il controllo delle immagini non autorizzate è quindi necessario configurare almeno un identificativo.

### Limiti specifici per progetto

È possibile definire soglie dedicate a singoli progetti attraverso project_limits.

Esempio:

    project_limits:
      project-id:
        max_ram_mb: 8192
        max_vcpus: 4

I limiti specifici sostituiscono quelli globali per il progetto interessato. I parametri non specificati continuano a utilizzare i rispettivi valori globali.

## API REST

L API utilizza la porta 9876 e, per impostazione predefinita, ascolta sull’indirizzo 127.0.0.1.

| Metodo | Endpoint | Descrizione | Autorizzazione |
|---|---|---|---|
| GET | / | Dashboard web. | Pubblico |
| GET | /health | Stato del servizio. | Pubblico |
| GET | /auth-info | Informazioni sull’utente autenticato. | Autenticato |
| POST | /scan | Avvio di una scansione manuale. | Admin |
| POST | /restore/<instance_id> | Ripristino di un’istanza. | Admin |
| GET | /scans | Elenco delle scansioni. | Autenticato |
| GET | /violations | Elenco delle violazioni. | Autenticato |
| GET | /quarantine-events | Storico degli eventi di quarantena. | Autenticato |
| GET | /dashboard-data | Dati aggregati per la dashboard. | Autenticato |
| GET | /policy | Consultazione della policy. | Autenticato |
| PUT | /policy | Aggiornamento della policy. | Admin |
| GET | /audit-events | Storico delle operazioni amministrative. | Admin |

L autenticazione degli endpoint protetti è gestita tramite Keystone Middleware. Le operazioni amministrative richiedono il ruolo admin.

Gli endpoint / e /health sono accessibili senza autenticazione.

## Database

Guardrail utilizza SQLite per conservare:

- Storico delle scansioni.
- Violazioni rilevate e relativo stato.
- Tentativi e risultati delle operazioni di quarantena.
- Eventi di ripristino.
- Conteggi degli stati ERROR consecutivi.
- Eventi di audit amministrativo.

Il database runtime si trova in:

    /var/lib/guardrail/guardrail.db

## Test

I test automatici coprono le regole di conformità, il controller, il database, la quarantena, lo scheduler e le API.

Per eseguire l’intera suite nell’ambiente Python DevStack:

    /opt/stack/data/venv/bin/python -m unittest discover -s tests -v

Per verificare la sintassi dei moduli:

    /opt/stack/data/venv/bin/python -m compileall -q guardrail tests

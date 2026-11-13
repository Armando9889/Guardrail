# Guardrail

Guardrail è un plugin per DevStack che estende OpenStack con un sistema
automatizzato di verifica della conformità delle istanze gestite da
Nova.

Il servizio esegue scansioni periodiche o manuali, confronta le
caratteristiche delle macchine virtuali (VM) con le policy definite
dall'amministratore e registra le violazioni rilevate in un database
SQLite.

In presenza di violazioni critiche, Guardrail può attivare una procedura
di quarantena automatica attraverso Neutron, limitando la connettività
di rete delle istanze interessate mediante l'applicazione di un Security
Group dedicato.

I risultati dei controlli e le operazioni effettuate sono consultabili
attraverso un'API REST e una dashboard web. L'autenticazione e
l'autorizzazione delle operazioni amministrative sono integrate con
Keystone.

## Funzionalità principali

-   Scansione periodica automatizzata delle istanze Nova.
-   Avvio manuale delle scansioni tramite API REST.
-   Verifica di otto regole di conformità.
-   Configurazione centralizzata delle policy.
-   Gestione dei limiti globali e specifici per progetto.
-   Registrazione dello storico delle scansioni e delle violazioni.
-   Quarantena automatica configurabile per le violazioni critiche.
-   Applicazione reale dei Security Group Neutron per isolare le
    istanze.
-   Ripristino manuale dei Security Group originali.
-   Registrazione degli eventi di quarantena e ripristino.
-   Dashboard web per il monitoraggio delle attività.
-   Autenticazione e autorizzazione tramite Keystone.
-   Registrazione delle operazioni amministrative tramite audit log.

## Regole di conformità

Guardrail implementa otto regole per verificare la conformità delle
istanze Nova alle policy definite dall'amministratore.

  -----------------------------------------------------------------------
  Regola                              Descrizione
  ----------------------------------- -----------------------------------
  R1                                  Verifica la presenza e il formato
                                      corretto del metadato `owner`.

  R2                                  Verifica che la RAM assegnata alla
                                      singola VM non superi il limite
                                      configurato.

  R3                                  Verifica che il numero di vCPU
                                      assegnate alla singola VM non
                                      superi il limite configurato.

  R4                                  Verifica che l'immagine utilizzata
                                      dalla VM appartenga alla lista
                                      delle immagini autorizzate.

  R5                                  Verifica che il nome della VM
                                      rispetti il pattern e la lunghezza
                                      massima configurati.

  R6                                  Verifica che il metadato
                                      `security_profile` sia presente e
                                      abbia un valore ammesso.

  R7                                  Rileva le VM che permangono nello
                                      stato `ERROR` per il numero di
                                      scansioni consecutive configurato.

  R8                                  Verifica che il consumo aggregato
                                      di RAM e vCPU del progetto non
                                      superi le soglie configurate.
  -----------------------------------------------------------------------

Per R6 sono ammessi i seguenti profili:

-   `web`
-   `database`
-   `general`

R2 e R3 supportano limiti specifici per progetto, utilizzando i limiti
globali quando non è presente una configurazione dedicata.

R8 effettua un controllo aggregato delle risorse utilizzate dalle
istanze appartenenti allo stesso progetto.

## Quarantena automatica

Guardrail integra un sistema di quarantena basato su Neutron, progettato
per isolare automaticamente le istanze che presentano determinate
violazioni critiche.

La configurazione prevede l'attivazione automatica della quarantena
esclusivamente per le seguenti regole:

-   **R4:** utilizzo di un'immagine non autorizzata.
-   **R6:** profilo di sicurezza mancante o non valido.

Le altre regole generano violazioni e vengono registrate nel database,
senza attivare automaticamente la quarantena.

### Funzionamento della quarantena

Quando viene rilevata una violazione appartenente a una delle regole
abilitate, il componente `QuarantineManager`:

1.  Identifica l'istanza Nova interessata.
2.  Individua le porte Neutron associate all'istanza.
3.  Recupera e conserva gli identificativi dei Security Group originali.
4.  Applica alle porte il Security Group dedicato
    `guardrail-quarantine`.
5.  Registra nel database l'operazione e il relativo risultato.

Il Security Group `guardrail-quarantine` deve contenere esattamente
una regola: SSH TCP sulla porta 22, IPv4, in ingresso (`ingress`), con
sorgente costituita da un singolo indirizzo IPv4 con prefisso `/32`.
Non sono ammesse ulteriori regole, comprese quelle in uscita (`egress`).

Prima di modificare le porte Neutron, Guardrail verifica la configurazione
del gruppo. Se il gruppo non esiste, non è possibile recuperarne le regole
oppure la configurazione non rispetta i requisiti, l'operazione viene
rifiutata senza modificare l'istanza.

### Ripristino della configurazione

Il ripristino della configurazione di rete è un'operazione manuale
riservata agli amministratori.

Attraverso l'API REST o la dashboard, l'amministratore può richiedere il
ripristino dell'istanza.

Guardrail recupera gli identificativi dei Security Group originali
registrati durante la quarantena e li riapplica alle porte Neutron
interessate.

L'operazione viene registrata nel database, mantenendo lo storico degli
eventi di quarantena e ripristino.

### Modalità dry-run e modalità reale

Il parametro `quarantine_dry_run` permette di scegliere tra due modalità
operative.

**Modalità simulata (`dry-run`):**

-   Simula l'esecuzione della quarantena.
-   Registra gli eventi e i risultati dell'operazione.
-   Non modifica effettivamente i Security Group delle porte Neutron.

**Modalità reale:**

-   Modifica effettivamente la configurazione dei Security Group
    attraverso Neutron.
-   Applica il Security Group di quarantena alle porte dell'istanza.
-   Conserva la configurazione originale per consentire il ripristino
    manuale.

La modalità simulata è prevista nella configurazione predefinita. Per
abilitare gli interventi effettivi è necessario impostare:

``` json
{
  "quarantine_dry_run": false
}
```

La modalità reale è stata verificata nell'ambiente DevStack utilizzato
per lo sviluppo del progetto, sia con un'istanza in stato `SHUTOFF` sia
con un'istanza in stato `ACTIVE`.

### Verifiche della quarantena reale

Le prove effettuate nell'ambiente OpenStack hanno verificato:

-   Rilevamento di una violazione critica associata a una regola
    abilitata alla quarantena automatica.
-   Individuazione delle porte Neutron associate all'istanza.
-   Applicazione effettiva del Security Group `guardrail-quarantine`.
-   Sostituzione dei Security Group originali sulle porte interessate.
-   Registrazione dell'evento di quarantena nel database.
-   Ripristino dei Security Group originali.
-   Registrazione dell'evento di ripristino.

La procedura è stata verificata sia con una VM in stato `SHUTOFF` sia
con una VM in stato `ACTIVE`. È stata quindi verificata la modifica
effettiva della configurazione di rete tramite Neutron anche su
un'istanza in esecuzione.

## Architettura

Guardrail è organizzato in componenti modulari, ciascuno responsabile di
una specifica funzionalità.

  -----------------------------------------------------------------------
  Componente                          Responsabilità
  ----------------------------------- -----------------------------------
  `guardrail/controller.py`           Coordina le scansioni, applica le
                                      policy e gestisce le violazioni.

  `guardrail/rules.py`                Implementa i controlli di
                                      conformità sulle istanze.

  `guardrail/quarantine.py`           Gestisce le operazioni di
                                      quarantena e ripristino attraverso
                                      Neutron.

  `guardrail/database.py`             Gestisce la persistenza SQLite di
                                      scansioni, violazioni ed eventi.

  `guardrail/api.py`                  Espone le API REST e la dashboard
                                      web.

  `guardrail/scheduler.py`            Esegue le scansioni periodiche.

  `devstack/plugin.sh`                Gestisce installazione,
                                      configurazione, avvio e arresto del
                                      plugin DevStack.

  `devstack/settings`                 Definisce le impostazioni e i
                                      servizi del plugin.

  `etc/config.json`                   Contiene la configurazione
                                      predefinita delle policy.

  `tests/`                            Contiene i test automatici del
                                      progetto.
  -----------------------------------------------------------------------

## Tecnologie utilizzate

-   **OpenStack Nova:** gestione e interrogazione delle istanze
    virtuali.
-   **OpenStack Neutron:** gestione delle porte di rete e dei Security
    Group.
-   **OpenStack Keystone:** autenticazione e autorizzazione.
-   **DevStack:** installazione e integrazione del plugin nell'ambiente
    OpenStack.
-   **Python 3:** implementazione della logica applicativa.
-   **Flask:** realizzazione dell'API REST e della dashboard.
-   **openstacksdk:** comunicazione con i servizi OpenStack.
-   **SQLite:** persistenza dei dati e dello storico delle operazioni.
-   **systemd:** gestione dei servizi Guardrail.
-   **Apache HTTP Server:** reverse proxy per l'integrazione della
    dashboard con Horizon.

## Requisiti

Per installare Guardrail è necessario disporre di:

-   Un ambiente Ubuntu compatibile con DevStack.
-   DevStack correttamente installato e funzionante.
-   OpenStack Nova, Neutron e Keystone attivi.
-   Python 3.
-   Git.
-   Accesso amministrativo ai servizi OpenStack.
-   Dipendenze Python definite nel file `requirements.txt`.

## Installazione tramite DevStack

Clonare il repository:

``` bash
git clone https://github.com/Armando9889/Guardrail.git
```

Inserire il plugin nella configurazione DevStack, modificando
`local.conf`:

``` ini
enable_plugin guardrail-lite https://github.com/Armando9889/Guardrail.git main
```

Avviare DevStack:

``` bash
cd /opt/stack/devstack
./stack.sh
```

Il plugin verifica la disponibilità dell'ambiente Python e delle dipendenze necessarie, predispone la directory di configurazione e registra i servizi Guardrail. Il virtual environment e le dipendenze Python devono essere predisposti preventivamente.

## Servizi

Il plugin Guardrail viene abilitato come servizio DevStack e avvia
due processi gestiti tramite systemd:

  ----------------------------------------------------------------------------
  Servizio                                 Responsabilità
  ---------------------------------------- -----------------------------------
  `devstack@guardrail-api.service`         Espone l'API REST e la dashboard
                                           web.

  `devstack@guardrail-scheduler.service`   Esegue le scansioni periodiche.
  ----------------------------------------------------------------------------

Per verificare lo stato dei servizi:

``` bash
sudo systemctl status devstack@guardrail-api.service
sudo systemctl status devstack@guardrail-scheduler.service
```

Per verificarne rapidamente lo stato:

``` bash
sudo systemctl is-active devstack@guardrail-api.service
sudo systemctl is-active devstack@guardrail-scheduler.service
```

## Configurazione

Il file di configurazione utilizzato dal servizio è:

``` text
/etc/guardrail/config.json
```

Le principali opzioni disponibili sono:

  -----------------------------------------------------------------------
  Parametro                           Descrizione
  ----------------------------------- -----------------------------------
  `scan_interval_seconds`             Intervallo, in secondi, tra le
                                      scansioni periodiche.

  `max_ram_mb`                        Limite globale di RAM per singola
                                      VM.

  `max_vcpus`                         Limite globale di vCPU per singola
                                      VM.

  `allowed_image_ids`                 Elenco degli identificativi delle
                                      immagini autorizzate.

  `name_pattern`                      Espressione regolare per la
                                      validazione dei nomi delle VM.

  `max_name_length`                   Lunghezza massima consentita per il
                                      nome della VM.

  `error_scan_threshold`              Numero di scansioni consecutive in
                                      stato ERROR prima della
                                      segnalazione R7.

  `max_project_ram_mb`                Limite globale di RAM aggregata per
                                      progetto.

  `max_project_vcpus`                 Limite globale di vCPU aggregate
                                      per progetto.

  `auto_quarantine_rules`             Regole abilitate alla quarantena
                                      automatica.

  `quarantine_security_group`         Nome del Security Group utilizzato
                                      per la quarantena.

  `quarantine_dry_run`                Abilita o disabilita la modalità
                                      simulata.

  `project_limits`                    Limiti specifici per singolo
                                      progetto.
  -----------------------------------------------------------------------

Esempio di configurazione:

``` json
{
  "scan_interval_seconds": 300,
  "max_ram_mb": 4096,
  "max_vcpus": 2,
  "allowed_image_ids": [],
  "name_pattern": "^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
  "max_name_length": 50,
  "error_scan_threshold": 3,
  "max_project_ram_mb": 8192,
  "max_project_vcpus": 8,
  "auto_quarantine_rules": ["R4", "R6"],
  "quarantine_security_group": "guardrail-quarantine",
  "quarantine_dry_run": true,
  "project_limits": {
    "PROJECT_ID": {
      "max_ram_mb": 8192,
      "max_vcpus": 4
    }
  }
}
```

`allowed_image_ids` contiene gli identificativi delle immagini Glance
autorizzate. Se la lista è vuota, il controllo R4 è disabilitato e non
vengono applicate restrizioni sulle immagini utilizzate dalle istanze.

`project_limits` permette di definire soglie specifiche per singolo
progetto. La chiave deve corrispondere all'identificativo del progetto
OpenStack.

Per abilitare la quarantena reale, impostare `quarantine_dry_run` a
`false`. La configurazione effettiva si trova in
`/etc/guardrail/config.json`.

## API REST

Guardrail espone un'API REST attraverso Flask. Gli endpoint `/` e
`/health` sono pubblici. Tutti gli altri endpoint richiedono
autenticazione Keystone; le operazioni amministrative richiedono inoltre
un utente con ruolo amministrativo.

  --------------------------------------------------------------------------------
  Metodo            Endpoint                   Descrizione       Autorizzazione
  ----------------- -------------------------- ----------------- -----------------
  GET               `/`                        Dashboard web.    Pubblica

  GET               `/health`                  Verifica dello    Pubblica
                                               stato del         
                                               servizio.         

  GET               `/auth-info`               Informazioni      Autenticato
                                               sull'utente       
                                               autenticato.      

  POST              `/scan`                    Avvia una         Admin
                                               scansione         
                                               manuale.          

  POST              `/restore/<instance_id>`   Ripristina i      Admin
                                               Security Group    
                                               originali di      
                                               un'istanza.       

  GET               `/scans`                   Elenco delle      Autenticato
                                               scansioni         
                                               eseguite.         

  GET               `/violations`              Elenco delle      Autenticato
                                               violazioni        
                                               rilevate.         

  GET               `/quarantine-events`       Storico degli     Autenticato
                                               eventi di         
                                               quarantena e      
                                               ripristino.       

  GET               `/dashboard-data`          Dati aggregati    Autenticato
                                               per la dashboard. 

  GET               `/policy`                  Consulta la       Autenticato
                                               configurazione    
                                               delle policy.     

  PUT               `/policy`                  Aggiorna le       Admin
                                               policy.           

  GET               `/audit-events`            Consulta gli      Admin
                                               eventi di audit.  
  --------------------------------------------------------------------------------

L'API è raggiungibile direttamente all'indirizzo:

``` text
http://127.0.0.1:9876
```

## Dashboard web

Guardrail include una dashboard web realizzata con Flask e HTML, CSS e
JavaScript.

La dashboard permette di:

-   Visualizzare lo stato generale del servizio.
-   Consultare i risultati delle scansioni.
-   Visualizzare le violazioni rilevate.
-   Consultare gli eventi di quarantena e ripristino.
-   Avviare scansioni manuali.
-   Richiedere il ripristino delle istanze in quarantena.
-   Consultare e gestire le policy in base ai privilegi dell'utente.
-   Consultare gli eventi di audit quando autorizzati.

La dashboard è raggiungibile direttamente tramite il servizio Flask:

``` text
http://127.0.0.1:9876/
```

In questo modo la dashboard può essere raggiunta attraverso lo stesso
host utilizzato da Horizon, senza esporre direttamente Flask sulla rete.

## Database e storico

Guardrail utilizza SQLite per memorizzare i dati necessari al
monitoraggio e alla gestione delle violazioni.

Il database è conservato nel percorso:

``` text
/var/lib/guardrail/guardrail.db
```

La persistenza comprende:

-   Storico delle scansioni.
-   Violazioni rilevate e relativo stato.
-   Numero di occorrenze delle violazioni.
-   Tentativi e risultati delle operazioni di quarantena.
-   Eventi di quarantena e ripristino.
-   Conteggio degli stati ERROR consecutivi.
-   Eventi di audit delle operazioni amministrative.

Lo storico permette di ricostruire le attività svolte dal sistema e di
verificare gli interventi effettuati sulle istanze.

## Test

Il progetto include test automatici per verificare il comportamento dei
principali componenti applicativi.

I test riguardano, tra gli altri:

-   Verifica delle regole di conformità.
-   Gestione delle scansioni.
-   Registrazione delle violazioni.
-   Gestione del database.
-   Funzionamento della quarantena.
-   Modalità simulata e modalità reale.
-   Ripristino dei Security Group originali.
-   Gestione degli eventi e dei risultati delle operazioni.

Per eseguire la suite di test:

``` bash
cd /opt/stack/guardrail
/opt/stack/data/venv/bin/python -m unittest discover -s tests -v
```

Per verificare la compilazione dei moduli Python:

``` bash
/opt/stack/data/venv/bin/python -m compileall -q guardrail tests
```

## Repository

Il codice sorgente e la documentazione del progetto sono disponibili su
GitHub:

https://github.com/Armando9889/Guardrail

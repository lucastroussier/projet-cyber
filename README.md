# CyberAudit

CyberAudit est un prototype d'outil de cybersecurite defensif, entierement en Python, destine aux audits **autorises** de reseaux internes et de postes Windows.

Fonctionnalites incluses :

- decouverte des hotes sur un sous-reseau
- profils de scan `quick`, `standard`, `windows`, `infrastructure` et `full`
- detection de ports TCP ouverts et services exposes
- decouverte UDP ciblee : NetBIOS, SNMP read-only, mDNS, LLMNR, DNS/NTP selon profil
- cartographie reseau basique avec ARP, cache voisin Windows/Linux et DNS inverse
- audit local Windows : mises a jour, pare-feu, Defender, BitLocker, administrateurs locaux, services, partages, logiciels
- mode agent/collecteur pour auditer un poste distant sans WinRM
- correlation CVE heuristique via l'API NVD 2.0
- generation de rapports HTML et JSON
- interface web legere en Flask

## Important

Cet outil doit etre utilise uniquement sur des systemes et reseaux dont vous avez l'autorisation d'audit.

Par defaut, le scan reseau refuse les cibles hors plages privees RFC1918, sauf option explicite.

Le mode agent est volontaire : rien n'est installe en persistance, l'agent doit etre lance manuellement sur le poste audite.

## Installation

```powershell
cd "C:\prog\projet cyber"
python -m pip install -e .
```

## Usage CLI

Audit local Windows uniquement :

```powershell
python -m cyberaudit scan --skip-network --audit-localhost --output reports
```

Scan reseau + audit local avec profil standard :

```powershell
python -m cyberaudit scan --network 192.168.1.0/24 --scan-profile standard --audit-localhost --output reports
```

Scan oriente parc Windows :

```powershell
python -m cyberaudit scan --network 192.168.1.0/24 --scan-profile windows --output reports
```

## Audit d'un poste distant avec agent

Exemple : PC1 est le collecteur et PC2 est le poste a auditer.

### 1. Generer l'executable agent sur PC1

Sur **PC1**, generer `cyberaudit-agent.exe` :

```powershell
python -m cyberaudit build-agent --output dist
```

L'executable sera cree ici :

```text
dist\cyberaudit-agent.exe
```

Copiez uniquement ce fichier sur **PC2**.

### 2. Demarrer le collecteur sur PC1

Sur **PC1**, demarrer le collecteur :

```powershell
python -m cyberaudit collector --host 0.0.0.0 --port 8090 --token "secret-audit" --output reports
```

### 3. Lancer l'agent sur PC2

Sur **PC2**, lancer l'executable :

```powershell
.\cyberaudit-agent.exe --collector http://IP_DU_PC1:8090 --token "secret-audit" --agent-id "PC2" --scan-profile windows
```

Si vous double-cliquez sur `cyberaudit-agent.exe` sans argument, il demande l'URL du collecteur et le token dans la console.

Alternative si Python et le projet sont aussi installes sur PC2 :

```powershell
python -m cyberaudit agent --collector http://IP_DU_PC1:8090 --token "secret-audit" --agent-id "PC2" --scan-profile windows --output reports
```

L'agent realise un audit local Windows sur PC2, garde une copie locale du rapport dans `reports`, puis envoie le rapport JSON au collecteur sur PC1. Le collecteur met ensuite a jour un rapport consolide unique :

```text
reports\cyberaudit_agents_consolide.html
```

Pour auditer plusieurs PC, lancez le meme executable sur chaque poste avec un `--agent-id` different, par exemple `PC2`, `PC3`, `PC4`. Si un meme `--agent-id` renvoie un nouvel audit, son ancienne entree est remplacee dans le rapport consolide.

## Options utiles

- `--scan-profile quick|standard|windows|infrastructure|full`
- `--udp-discovery-ports 137,161,5353,5355`
- `--disable-udp-discovery`
- `--snmp-communities public,monitoring`
- `build-agent --output dist` pour generer `cyberaudit-agent.exe`
- `collector --token "secret-audit"` pour proteger la reception des rapports agents
- `agent --collector http://IP_DU_PC1:8090 --token "secret-audit" --scan-profile windows` pour envoyer l'audit local au collecteur avec le type d'analyse voulu

## Interface web

Lancer l'interface web locale :

```powershell
python -m cyberaudit serve --host 127.0.0.1 --port 8080 --output reports
```

Puis ouvrir [http://127.0.0.1:8080](http://127.0.0.1:8080).

## Lanceur Windows local

Depuis le dossier du projet, vous pouvez aussi utiliser le lanceur local :

```cmd
cyberaudit scan --skip-network --audit-localhost --output reports
```

Ce lanceur repose sur le fichier `cyberaudit.cmd` present a la racine du projet. Si vous lancez depuis PowerShell, utilisez `.\cyberaudit.cmd`.

## Architecture

- `src/cyberaudit/network.py` : decouverte reseau, scan de ports, UDP cible, bannieres simples
- `src/cyberaudit/windows_audit.py` : audit Windows local
- `src/cyberaudit/agent.py` : collecteur HTTP et agent d'envoi de rapport
- `src/cyberaudit/agent_exe.py` : point d'entree de l'executable agent autonome
- `src/cyberaudit/agent_builder.py` : generation PyInstaller de `cyberaudit-agent.exe`
- `src/cyberaudit/vuln.py` : correlation CVE via NVD
- `src/cyberaudit/orchestrator.py` : orchestration complete
- `src/cyberaudit/reporting.py` : rendu JSON/HTML
- `src/cyberaudit/webapp.py` : interface Flask

## Limites

- la cartographie reseau reste logique et non physique
- l'agent doit etre copie et lance volontairement sur le poste audite
- le collecteur doit etre joignable depuis le poste agent, par exemple via le port TCP 8090
- la decouverte UDP depend des reponses des equipements et peut rester silencieuse meme si un service existe
- la correlation CVE logicielle est heuristique : elle aide au tri mais ne remplace pas une validation humaine
- certains controles Windows demandent des privileges eleves pour etre complets

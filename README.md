# CyberAudit

CyberAudit est un outil Python d'audit defensif pour cartographier un reseau interne, auditer des postes Windows et consolider des rapports de securite.

Le projet est destine aux audits **autorises** uniquement. Il ne s'installe pas en persistance sur les postes agents : l'agent doit etre lance volontairement sur chaque machine auditee.

## Sommaire

- [Fonctionnalites](#fonctionnalites)
- [Prerequis](#prerequis)
- [Installation](#installation)
- [Demarrage rapide](#demarrage-rapide)
- [Interface web](#interface-web)
- [Audit avec agents Windows](#audit-avec-agents-windows)
- [Commandes CLI](#commandes-cli)
- [Rapports](#rapports)
- [CVE et cle API NVD](#cve-et-cle-api-nvd)
- [Bonnes pratiques de securite](#bonnes-pratiques-de-securite)
- [Depannage](#depannage)
- [Architecture](#architecture)
- [Limites](#limites)
- [Licence](#licence)

## Fonctionnalites

- Decouverte d'hotes sur sous-reseau.
- Profils de scan : `quick`, `standard`, `windows`, `infrastructure`, `full`.
- Detection de ports TCP ouverts et de services exposes.
- Decouverte UDP ciblee : NetBIOS, SNMP read-only, mDNS, LLMNR, DNS/NTP selon profil.
- Cartographie reseau basique avec ARP, cache voisin Windows/Linux et DNS inverse.
- Audit local Windows : correctifs, pare-feu, Defender, BitLocker, RDP/NLA, SMB, LLMNR, LSASS, Secure Boot/TPM, comptes locaux, services, ports exposes, partages, inventaire logiciel.
- Mode agent Windows pour auditer des postes distants sans WinRM.
- Interface web unique pour lancer les audits, preparer les agents, recevoir les rapports et les supprimer.
- Correlation CVE heuristique via l'API NVD 2.0 avec recherche CPE quand possible.
- Rapports HTML, JSON et export PDF depuis l'interface web.

## Prerequis

- Python `3.11` ou plus recent.
- Windows pour l'audit local complet.
- PowerShell disponible sur les postes Windows audites.
- Droits administrateur recommandes pour une collecte Windows plus complete.
- Acces reseau entre le poste agent et le poste qui heberge l'interface web.
- Optionnel : une cle API NVD pour accelerer et fiabiliser les recherches CVE.

## Installation

Depuis le dossier du projet :

```powershell
cd "C:\prog\projet cyber"
python -m pip install -e .
```

Pour generer l'executable agent autonome, installez aussi les dependances de build :

```powershell
python -m pip install -e ".[build]"
```

## Demarrage rapide

### Audit local depuis l'interface web

Lancer l'interface web locale :

```powershell
python -m cyberaudit serve --host 127.0.0.1 --port 8080 --output reports
```

Ouvrir ensuite :

```text
http://127.0.0.1:8080
```

Depuis l'interface, utilisez la section `Lancer une analyse`.

### Interface web accessible aux agents

Pour recevoir les rapports d'autres postes, lancez l'interface sur toutes les interfaces reseau :

```powershell
python -m cyberaudit serve --host 0.0.0.0 --port 8080 --token "secret-audit" --output reports
```

Depuis PC1, ouvrez :

```text
http://127.0.0.1:8080
```

Depuis un autre poste du reseau, utilisez l'adresse IP de PC1 :

```text
http://IP_PC1:8080
```

## Interface web

L'interface web permet de :

- lancer un audit local ou reseau ;
- telecharger `cyberaudit-agent.exe` ;
- generer une commande agent pre-remplie ;
- proposer un `Agent ID` aleatoire, modifiable avant copie ;
- recevoir les rapports agents sur `/api/agent/report` ;
- consulter les rapports HTML ;
- telecharger les rapports en PDF ;
- supprimer un rapport HTML et son JSON associe.

Si l'interface est lancee avec `--host 127.0.0.1`, elle est accessible seulement depuis PC1. Pour les agents distants, utilisez `--host 0.0.0.0`.

## Audit avec agents Windows

### 1. Generer l'agent sur PC1

```powershell
python -m cyberaudit build-agent --output dist
```

L'executable est cree ici :

```text
dist\cyberaudit-agent.exe
```

### 2. Lancer l'interface web sur PC1

```powershell
python -m cyberaudit serve --host 0.0.0.0 --port 8080 --token "secret-audit" --output reports
```

### 3. Preparer la commande agent

Dans la section `Agents Windows` de l'interface web :

1. telechargez l'agent ;
2. copiez l'executable sur le poste a auditer ;
3. gardez l'`Agent ID` aleatoire propose ou remplacez-le par un nom lisible ;
4. choisissez le profil ;
5. ajoutez une cle API NVD si disponible ;
6. copiez la commande generee.

Exemple de commande generee :

```powershell
.\cyberaudit-agent.exe --collector http://IP_PC1:8080 --token "secret-audit" --agent-id "AGENT-1A2B3C4D" --scan-profile full --max-cve-products 0 --max-cves-per-product 10 --nvd-api-key "VOTRE_CLE_NVD"
```

Remplacez `IP_PC1` par la vraie adresse IPv4 de PC1.

### 4. Verifier la connectivite

Depuis le poste agent :

```powershell
Test-NetConnection IP_PC1 -Port 8080
```

Le resultat attendu est :

```text
TcpTestSucceeded : True
```

Si le test echoue, ouvrez le port sur PC1 depuis un PowerShell administrateur :

```powershell
New-NetFirewallRule -DisplayName "CyberAudit Web 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
```

## Commandes CLI

Audit Windows local uniquement :

```powershell
python -m cyberaudit scan --skip-network --audit-localhost --output reports
```

Scan reseau avec profil standard :

```powershell
python -m cyberaudit scan --network 192.168.1.0/24 --scan-profile standard --audit-localhost --output reports
```

Scan oriente parc Windows :

```powershell
python -m cyberaudit scan --network 192.168.1.0/24 --scan-profile windows --output reports
```

Interface web :

```powershell
python -m cyberaudit serve --host 0.0.0.0 --port 8080 --token "secret-audit" --output reports
```

Agent avec Python installe sur le poste cible :

```powershell
python -m cyberaudit agent --collector http://IP_PC1:8080 --token "secret-audit" --agent-id "AGENT-1A2B3C4D" --scan-profile full --output reports
```

Options utiles :

- `--scan-profile quick|standard|windows|infrastructure|full`
- `--max-cve-products 0` pour tenter la correlation NVD sur tous les logiciels inventories
- `--max-cves-per-product 10` pour conserver plus de CVE par logiciel
- `--nvd-api-key` pour utiliser une cle API NVD
- `--allow-non-private` pour autoriser explicitement les cibles hors plages privees
- `--disable-udp-discovery` pour desactiver la decouverte UDP

## Rapports

Les rapports sont ecrits dans le dossier configure avec `--output`, par defaut :

```text
reports\
```

Formats disponibles :

- HTML : consultation dans un navigateur ;
- JSON : donnees structurees et rechargement par l'outil ;
- PDF : export telechargeable depuis l'interface web.

Le rapport consolide des agents est cree ici :

```text
reports\cyberaudit_agents_consolide.html
reports\cyberaudit_agents_consolide.json
```

Depuis l'interface web, le bouton `Supprimer` efface le HTML selectionne et le JSON associe.

## CVE et cle API NVD

La correlation CVE utilise l'API NVD 2.0. Elle reste heuristique : elle aide a prioriser les verifications, mais ne remplace pas la validation humaine de la version exacte, des correctifs installes et du contexte d'exposition.

Pour eviter de saisir la cle dans l'historique de commande, vous pouvez la stocker dans un fichier local ignore par Git, par exemple `apikay.txt` :

```powershell
$NVD_KEY = (Get-Content .\apikay.txt -Raw).Trim()
python -m cyberaudit scan --skip-network --audit-localhost --scan-profile full --max-cve-products 0 --max-cves-per-product 10 --nvd-api-key $NVD_KEY --output reports
```

Ne publiez jamais une vraie cle API dans GitHub, dans une issue ou dans un rapport partage publiquement.

## Bonnes pratiques de securite

- Auditez uniquement des systemes pour lesquels vous avez une autorisation explicite.
- Changez le token `secret-audit` avant un usage reel.
- Lancez l'interface en `127.0.0.1` si vous n'avez pas besoin d'agents distants.
- Si vous utilisez `--host 0.0.0.0`, limitez l'acces reseau au port `8080`.
- Gardez les cles API et tokens hors du depot Git.
- Relancez l'agent en administrateur quand un audit Windows complet est attendu.
- Validez manuellement les CVE critiques avant d'en tirer une conclusion definitive.

## Depannage

`Failed to resolve 'ip_du_pc1'`

Remplacez `IP_PC1` ou `IP_DU_PC1` par la vraie adresse IPv4 de PC1, par exemple `192.168.1.42`.

`TcpTestSucceeded : False`

PC2 ne joint pas PC1 sur le port `8080`. Verifiez l'adresse IP, le pare-feu Windows et le mode `--host 0.0.0.0`.

`401 Unauthorized`

Le token utilise par l'agent ne correspond pas au token de l'interface web.

Analyse CVE tres lente

Utilisez une cle API NVD ou reduisez `--max-cve-products`, par exemple `--max-cve-products 20`.

Peu de donnees Windows

Relancez PowerShell ou l'agent en administrateur.

## Architecture

```text
src/cyberaudit/
  agent.py          # reception et consolidation des rapports agents
  agent_builder.py  # generation PyInstaller de cyberaudit-agent.exe
  agent_exe.py      # point d'entree de l'agent autonome
  config.py         # profils de scan et configuration
  main.py           # CLI
  models.py         # modeles de donnees
  network.py        # decouverte reseau et scan de ports
  orchestrator.py   # orchestration de l'audit
  reporting.py      # generation HTML, JSON et PDF
  vuln.py           # correlation CVE via NVD
  webapp.py         # interface web Flask
  windows_audit.py  # collecte locale Windows
```

## Limites

- CyberAudit est un prototype defensif.
- Aucune solution ne peut garantir la detection de toutes les failles.
- La cartographie reseau reste logique, pas physique.
- La decouverte UDP depend des reponses des equipements et peut rester silencieuse.
- La correlation CVE depend de la qualite de l'inventaire, des versions detectees et des donnees NVD.
- Certains controles Windows demandent des privileges eleves.

## Licence

Aucune licence n'est publiee pour le moment. Ajoutez un fichier `LICENSE` avant toute distribution publique du projet.

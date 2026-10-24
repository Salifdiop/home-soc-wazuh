# 🛡️ Home SOC — Détection d'intrusion avec Wazuh (FIM + MITRE ATT&CK)

Mise en place d'un mini **Security Operations Center (SOC)** dans un lab virtualisé : collecte des événements d'un poste Windows, surveillance de l'intégrité des fichiers (**File Integrity Monitoring**), investigation d'une attaque simulée et rattachement des détections au framework **MITRE ATT&CK**.

> Projet réalisé par **Salif Diop** — Licence Professionnelle Télécommunications et Informatique, ESMT Dakar (Administration Systèmes et Réseaux).

---

## 📋 Sommaire

1. [Objectifs](#-objectifs)
2. [Architecture](#-architecture)
3. [Installation du serveur Wazuh](#-installation-du-serveur-wazuh)
4. [Déploiement de l'agent Windows](#-déploiement-de-lagent-windows)
5. [Configuration du FIM](#-configuration-du-fim)
6. [Scénario d'attaque](#-scénario-dattaque)
7. [Investigation](#-investigation)
8. [Mapping MITRE ATT&CK](#-mapping-mitre-attck)
9. [Règles de détection personnalisées](#-règles-de-détection-personnalisées)
10. [Difficultés rencontrées et solutions](#-difficultés-rencontrées-et-solutions)
11. [Compétences acquises](#-compétences-acquises)

---

## 🎯 Objectifs

- Déployer un SIEM open source (**Wazuh 4.14**) sur un serveur Ubuntu.
- Connecter un endpoint Windows et collecter ses événements de sécurité.
- Surveiller en temps réel un dossier sensible avec le **FIM** et le mode **whodata** (identification de l'utilisateur et du processus responsables).
- Simuler une attaque, investiguer les alertes et reconstituer la chronologie.
- Mapper les détections sur **MITRE ATT&CK** et écrire des **règles de détection personnalisées**.

---

## 🏗️ Architecture

```
                    ┌──────────────── Internet ────────────────┐
                    │                                          │
             (accès par pont)                                  │
                    │                                          │
┌───────────────────┴────────────┐          ┌─────────────────┴──────────────┐
│  VM Ubuntu Server 22.04         │          │  PC Windows (hôte)              │
│  « SOC-Wazuh »                  │          │  Agent Wazuh « PC-SALIF »       │
│                                 │          │                                 │
│  • Wazuh manager                │◄────────►│  • FIM sur C:\Sensible          │
│  • Wazuh indexer                │ 1514/1515│  • whodata activé               │
│  • Wazuh dashboard (443)        │   TCP    │                                 │
│                                 │          │                                 │
│  enp0s8 : 192.168.56.10/24      │          │  192.168.56.1/24                │
└─────────────────────────────────┘          └─────────────────────────────────┘
            Réseau privé hôte VirtualBox : 192.168.56.0/24
```

| Élément | Détail |
|---|---|
| Hyperviseur | VirtualBox 7 |
| Serveur SIEM | Ubuntu Server 22.04, 2 vCPU, 4 Go RAM, 48 Go (LVM) |
| SIEM | Wazuh 4.14.9 (manager + indexer + dashboard sur un seul hôte) |
| Endpoint | PC Windows hôte, agent Wazuh `PC-SALIF` |
| Réseau du lab | Réseau privé hôte `192.168.56.0/24` (communication agent ↔ serveur) |
| Accès Internet | Carte en accès par pont (`enp0s3`, DHCP) |

📸 *Capture : `screenshots/01-architecture.png`*

---

## ⚙️ Installation du serveur Wazuh

### 1. Préparation d'Ubuntu

Configuration réseau statique (Netplan), après désactivation de la gestion réseau par cloud-init :

```bash
echo "network: {config: disabled}" | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```

`/etc/netplan/01-lab.yaml` :

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses: [192.168.56.10/24]
```

```bash
sudo chmod 600 /etc/netplan/01-lab.yaml
sudo netplan apply
```

### 2. Installation tout-en-un

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
tmux new -s wazuh                     # session persistante (voir Difficultés)
sudo bash ./wazuh-install.sh -a
```

### 3. Vérification et durcissement

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager
# Désactivation des mises à jour automatiques du dépôt Wazuh
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

📸 *Captures : `screenshots/02-installation-ok.png`, `screenshots/03-services-running.png`*

---

## 💻 Déploiement de l'agent Windows

Test de la connectivité depuis le poste Windows :

```powershell
Test-NetConnection 192.168.56.10 -Port 1514   # TcpTestSucceeded : True
Test-NetConnection 192.168.56.10 -Port 1515   # TcpTestSucceeded : True
```

Déploiement depuis le dashboard (**Agents management → Deploy new agent**), avec comme adresse serveur `192.168.56.10` et comme nom `PC-SALIF`, puis :

```powershell
NET START Wazuh
```

📸 *Capture : `screenshots/04-agent-actif.png`*

---

## 📁 Configuration du FIM

Dossier surveillé : `C:\Sensible`, contenant des fichiers simulant des données confidentielles (`salaires.txt`, `config.txt`).

Ajout dans `C:\Program Files (x86)\ossec-agent\ossec.conf`, section `<syscheck>` :

```xml
<directories check_all="yes" whodata="yes" report_changes="yes">C:\Sensible</directories>
```

| Option | Rôle |
|---|---|
| `whodata="yes"` | Détection en temps réel avec **l'utilisateur** et **le processus** responsables |
| `report_changes="yes"` | Affiche le **contenu modifié** (diff) |
| `check_all="yes"` | Contrôle du hash, de la taille, des permissions et du propriétaire |

```powershell
Restart-Service -Name wazuh
```

📸 *Capture : `screenshots/05-ossec-conf-syscheck.png`*

---

## 💥 Scénario d'attaque

Un utilisateur local à faibles privilèges, `stagiaire`, est créé pour simuler un acteur malveillant interne :

```powershell
net user stagiaire <mot_de_passe> /add
runas /user:stagiaire powershell
```

Depuis la session du stagiaire, trois actions sont exécutées à la suite :

```powershell
Add-Content C:\Sensible\salaires.txt "Salaire modifie : 9 999 999 FCFA" -Encoding utf8   # falsification
"malware simule" | Out-File C:\Sensible\payload.ps1 -Encoding utf8                      # dépôt d'un script
Remove-Item C:\Sensible\config.txt                                                       # effacement
```

---

## 🔎 Investigation

Les alertes ont été analysées dans **File Integrity Monitoring → Events**, en ajoutant les colonnes `rule.id`, `rule.level`, `syscheck.audit.user.name`, `syscheck.audit.process.name`, `syscheck.diff` et `rule.mitre.id`.

### Chronologie (règles personnalisées actives — 24/10/2026)

| Heure | Fichier | Événement | Utilisateur | Processus | Règle | Niveau | MITRE |
|---|---|---|---|---|---|---|---|
| 12:16:31.762 | `salaires.txt` | modifié | stagiaire | powershell.exe | 100100 | 12 | T1565.001 |
| 12:16:31.823 | `payload3.ps1` | ajouté | stagiaire | powershell.exe | 100102 | 12 | T1105 |
| 12:16:31.830 | `config.txt` | supprimé | stagiaire | powershell.exe | 100101 | 12 | T1070.004 |

### Constats

- **Quoi ?** Falsification d'un fichier de salaires, dépôt d'un script PowerShell, suppression d'un fichier de configuration.
- **Qui ?** Le compte local `stagiaire` (identifié grâce au whodata).
- **Comment ?** Via `powershell.exe`.
- **Quand ?** Les trois actions en **68 millisecondes**, ce qui indique une exécution **scriptée**, et non manuelle.
- **Preuve du contenu modifié :** le champ `syscheck.diff` montre exactement la ligne ajoutée (`> Salaire modifie : 9 999 999 FCFA`).
- **Distinction légitime / malveillant :** les modifications de préparation faites par l'administrateur (`HP`) apparaissent aussi, mais le whodata permet de les distinguer clairement de l'activité du stagiaire.

➡️ Voir le rapport complet : [`rapport-incident.md`](rapport-incident.md)

📸 *Captures : `screenshots/06-chronologie-alertes.png`, `screenshots/07-detail-alerte-diff.png`*

---

## 🧭 Mapping MITRE ATT&CK

| Action observée | Règle Wazuh | Technique MITRE ATT&CK | Tactique |
|---|---|---|---|
| Modification de `salaires.txt` | 550 → 100100 | **T1565.001** – Stored Data Manipulation | Impact |
| Suppression de `config.txt` | 553 → 100101 | **T1070.004** – Indicator Removal: File Deletion | Defense Evasion |
| Dépôt de `payload.ps1` | 554 → 100102 | **T1105** – Ingress Tool Transfer | Command and Control |

**Constat :** la règle Wazuh par défaut **554** (fichier ajouté) n'est associée à **aucune technique MITRE**. La règle personnalisée 100102 comble ce manque pour les scripts PowerShell déposés dans le dossier sensible.

📸 *Capture : `screenshots/08-matrice-mitre.png`*

---

## 🧩 Règles de détection personnalisées

Objectif : élever au **niveau critique (12)** toute activité sur le dossier sensible, et compléter la couverture MITRE.

`/var/ossec/etc/rules/local_rules.xml` :

```xml
<group name="syscheck,sensible,">
  <rule id="100100" level="12">
    <if_sid>550</if_sid>
    <field name="file" type="pcre2">(?i)sensible</field>
    <description>CRITIQUE : fichier sensible modifié dans C:\Sensible</description>
    <mitre><id>T1565.001</id></mitre>
  </rule>
  <rule id="100101" level="12">
    <if_sid>553</if_sid>
    <field name="file" type="pcre2">(?i)sensible</field>
    <description>CRITIQUE : fichier sensible supprimé dans C:\Sensible</description>
    <mitre><id>T1070.004</id></mitre>
  </rule>
  <rule id="100102" level="12">
    <if_sid>554</if_sid>
    <field name="file" type="pcre2">(?i)sensible.*\.ps1$</field>
    <description>CRITIQUE : script PowerShell déposé dans C:\Sensible</description>
    <mitre><id>T1105</id></mitre>
  </rule>
</group>
```

```bash
sudo /var/ossec/bin/wazuh-analysisd -t        # validation de la syntaxe
sudo systemctl restart wazuh-manager
sudo grep -E "Rule: 1001(00|01|02)" /var/ossec/logs/alerts/alerts.log
```

**Résultat :** les trois règles se déclenchent en niveau 12, avec leur technique MITRE.

📸 *Captures : `screenshots/09-local-rules.png`, `screenshots/10-alertes-niveau-12.png`*

---

## 🧱 Difficultés rencontrées et solutions

| # | Problème | Diagnostic | Solution |
|---|---|---|---|
| 1 | Échec de l'installation du dashboard | `/var/log/wazuh-install.log` : « disque plein ». Le volume LVM ne faisait que 23 Go (l'installeur Ubuntu n'alloue que la moitié du disque par défaut) | Extension à chaud : `pvresize`, `lvextend -l +100%FREE`, `resize2fs`, soit 48 Go |
| 2 | Installation interrompue en plein milieu | Coupure de la session SSH, qui a tué le processus d'installation | Désinstallation propre (`wazuh-install.sh -u`), puis réinstallation dans une session **tmux** persistante |
| 3 | IP statique perdue à chaque redémarrage | **cloud-init** régénérait le fichier Netplan au démarrage | Désactivation via `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg` et fichier Netplan dédié |
| 4 | Plus d'espace disque sur la machine physique (VM mise en pause) | Snapshots pris VM allumée, donc RAM sauvegardée (environ 4 Go par snapshot) | Suppression des snapshots obsolètes, snapshots désormais pris VM éteinte. Agent installé sur le PC hôte plutôt que dans une seconde VM |
| 5 | Diff illisible (`S > a > l > a...`) | PowerShell 5.1 écrit en **UTF-16** par défaut, avec des octets nuls entre chaque caractère | Création des fichiers en `-Encoding utf8` |
| 6 | Règles personnalisées non déclenchées | Syntaxe valide (`wazuh-analysisd -t`), mais filtre sur chemin Windows avec antislashs, et manager non redémarré | Filtre PCRE2 simplifié `(?i)sensible`, redémarrage du manager, vérification dans `alerts.log` |

---

## 🎓 Compétences acquises

- Déploiement et administration d'un **SIEM** (Wazuh : manager, indexer, dashboard).
- Administration Linux : **LVM**, Netplan, cloud-init, systemd, tmux.
- Réseau de lab VirtualBox : accès par pont, réseau privé hôte, tests de ports.
- **File Integrity Monitoring** avec whodata sur Windows.
- **Investigation d'alertes** : chronologie, attribution (utilisateur et processus), analyse de diff.
- **MITRE ATT&CK** : mapping des détections et identification des manques de couverture.
- **Detection engineering** : écriture et validation de règles Wazuh personnalisées (PCRE2, héritage `if_sid`).

---

## 📂 Structure du dépôt

```
home-soc-wazuh/
├── README.md
├── rapport-incident.md
├── config/
│   ├── ossec-syscheck.xml
│   └── local_rules.xml
└── screenshots/
    ├── 01-architecture.png
    ├── 02-installation-ok.png
    ├── 03-services-running.png
    ├── 04-agent-actif.png
    ├── 05-ossec-conf-syscheck.png
    ├── 06-chronologie-alertes.png
    ├── 07-detail-alerte-diff.png
    ├── 08-matrice-mitre.png
    ├── 09-local-rules.png
    └── 10-alertes-niveau-12.png
```

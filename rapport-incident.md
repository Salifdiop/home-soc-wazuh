# 📄 Rapport d'incident — INC-2026-001

| Champ | Valeur |
|---|---|
| **Référence** | INC-2026-001 |
| **Date de détection** | 24/10/2026, 12:16:31 |
| **Détecté par** | Wazuh FIM (whodata), règles 100100, 100101 et 100102 |
| **Sévérité** | 🔴 Critique (niveau 12) |
| **Endpoint concerné** | `PC-SALIF` (Windows), agent Wazuh actif |
| **Ressource ciblée** | Dossier sensible `C:\Sensible` |
| **Statut** | Clos (environnement de lab, attaque simulée) |
| **Analyste** | Salif Diop |

---

## 1. Résumé

Le **24/10/2026 à 12:16:31**, trois alertes critiques ont été levées par le module File Integrity Monitoring de Wazuh sur l'endpoint `PC-SALIF`. En **68 millisecondes**, le compte local à faibles privilèges `stagiaire` a, via PowerShell :

1. **modifié** un fichier de salaires (falsification de données) ;
2. **déposé** un script PowerShell (`payload3.ps1`) ;
3. **supprimé** un fichier de configuration (effacement).

La vitesse d'exécution indique une action **automatisée par script**. L'incident est qualifié de **manipulation de données par un acteur interne**.

---

## 2. Chronologie

| Heure (24/10/2026) | Fichier | Événement | Utilisateur | Processus | Règle | Niveau | MITRE |
|---|---|---|---|---|---|---|---|
| 12:16:31.762 | `c:\sensible\salaires.txt` | modifié | stagiaire | powershell.exe | 100100 | 12 | T1565.001 |
| 12:16:31.823 | `c:\sensible\payload3.ps1` | ajouté | stagiaire | powershell.exe | 100102 | 12 | T1105 |
| 12:16:31.830 | `c:\sensible\config.txt` | supprimé | stagiaire | powershell.exe | 100101 | 12 | T1070.004 |

**Activité antérieure observée :**
- **11:59:44 – 11:59:46** : modifications par le compte `HP` (administrateur), identifiées comme la **préparation légitime** du lab.
- **12:02:17 – 12:02:18** : première série d'actions identiques par `stagiaire`, détectée par les règles par défaut (550, 554, 553, niveaux 5 à 7).

---

## 3. Analyse

### 3.1 Qui ?
Le compte local **`stagiaire`**, identifié par le champ `syscheck.audit.user.name` grâce au mode **whodata**.

### 3.2 Comment ?
Par le processus **`powershell.exe`** (champ `syscheck.audit.process.name`).

### 3.3 Qu'est-ce qui a été modifié ?
Le champ `syscheck.diff` de l'alerte 100100 montre la ligne ajoutée dans `salaires.txt` :

```
> Salaire modifie : 9 999 999 FCFA
```
(série du 12:02:17 ; série du 12:16:31 : `> Test regle perso`)

### 3.4 Indicateurs de compromission (IOC)

| Type | Valeur |
|---|---|
| Compte | `stagiaire` (compte local) |
| Processus | `powershell.exe` |
| Fichiers déposés | `c:\sensible\payload.ps1`, `c:\sensible\payload3.ps1` |
| Fichier supprimé | `c:\sensible\config.txt` |
| Fichier altéré | `c:\sensible\salaires.txt` (hash SHA-256 modifié, voir `syscheck.sha256_after`) |

---

## 4. Mapping MITRE ATT&CK

| Technique | Nom | Tactique | Preuve |
|---|---|---|---|
| **T1565.001** | Data Manipulation: Stored Data Manipulation | Impact | Modification de `salaires.txt` |
| **T1105** | Ingress Tool Transfer | Command and Control | Dépôt de `payload3.ps1` |
| **T1070.004** | Indicator Removal: File Deletion | Defense Evasion | Suppression de `config.txt` |

> **Lacune de détection identifiée :** la règle par défaut 554 (fichier ajouté) n'était associée à aucune technique MITRE. Corrigé par la règle personnalisée **100102**.

---

## 5. Impact

- **Intégrité :** compromise. Un fichier de salaires a été falsifié.
- **Disponibilité :** dégradée. Un fichier de configuration a été supprimé.
- **Confidentialité :** aucune exfiltration observée dans le périmètre surveillé par le FIM.
- **Persistance potentielle :** un script PowerShell a été déposé (non exécuté dans ce scénario).

---

## 6. Réponse à incident

### Confinement
- Désactiver immédiatement le compte : `net user stagiaire /active:no`
- Isoler l'endpoint si une exécution du script est suspectée.

### Éradication
- Supprimer les scripts déposés (`payload*.ps1`) après en avoir conservé une copie et le hash comme preuve.

### Restauration
- Restaurer `salaires.txt` et `config.txt` depuis une sauvegarde saine.
- Vérifier l'intégrité des fichiers restaurés (comparaison de hash).

---

## 7. Recommandations

1. **Moindre privilège :** retirer au compte `stagiaire` et aux comptes standards les droits d'écriture sur `C:\Sensible` (ACL NTFS).
2. **PowerShell :** appliquer une politique d'exécution restrictive (`AllSigned`) et activer la journalisation PowerShell (Script Block Logging).
3. **Détection :** conserver les règles 100100 à 100102 et étendre le FIM aux autres dossiers sensibles.
4. **Réponse automatisée :** configurer une **Active Response** Wazuh pour désactiver automatiquement un compte en cas d'alerte de niveau 12 sur `C:\Sensible`.
5. **Sauvegardes :** mettre en place des sauvegardes régulières et testées des données sensibles.

---

## 8. Leçons apprises

- Le **whodata** est indispensable : sans lui, on sait **quoi** a changé, mais pas **qui** ni **avec quoi**.
- Les règles par défaut détectent l'événement, mais ne reflètent pas la **criticité métier** (niveau 5 à 7). Les règles personnalisées permettent d'adapter la sévérité au contexte.
- Le mapping MITRE révèle des **trous de couverture** (règle 554) qu'il faut combler activement.

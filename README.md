# Modification OpenSSH Win32 — Ajout du token `%w` dans `ChrootDirectory`

## 1. Contexte et problème

### Infrastructure
- Serveur RDS Windows Server 2019
- OpenSSH portable Win32 v8.1.0.0 en service (`sshd.exe`)
- Les utilisateurs se connectent via WinSCP (SFTP) avec leur compte Active Directory
- Chaque utilisateur dispose d'un dossier d'échange situé dans `E:\<domaine>\<utilisateur>`

### Configuration actuelle
```
ChrootDirectory E:\%u
```

Le token `%u` retourne le nom d'utilisateur complet au format `DOMAINE\utilisateur`
(ex : `frdom\T1234`), ce qui donne le chemin `E:\frdom\T1234`.

### Problème
Un second domaine AD (`pouet`) a été ajouté. Les utilisateurs migrés ont désormais
un identifiant de la forme `pouet\T1234`. Le token `%u` retourne donc un chemin
différent selon le domaine d'appartenance :

| Utilisateur       | `%u`            | Chemin résolu        |
|-------------------|-----------------|----------------------|
| `frdom\T1234`     | `frdom\T1234`   | `E:\frdom\T1234`     |
| `pouet\T1234`     | `pouet\T1234`   | `E:\pouet\T1234`     |

Ce comportement obligerait à maintenir deux arborescences de dossiers distinctes
ou à dupliquer les répertoires utilisateurs selon le domaine.

---

## 2. Solution retenue

Ajout d'un nouveau token `%w` dans le mécanisme de substitution de `ChrootDirectory`.

Ce token retourne le nom d'utilisateur **sans le préfixe domaine** :

| Utilisateur       | `%w`    | Chemin résolu     |
|-------------------|---------|-------------------|
| `frdom\T1234`     | `T1234` | `E:\users\T1234`  |
| `pouet\T1234`     | `T1234` | `E:\users\T1234`  |
| `T1234` (local)   | `T1234` | `E:\users\T1234`  |

La nouvelle configuration devient :
```
ChrootDirectory E:\users\%w
```

---

## 3. Modification du code source

### Fichier modifié : `session.c`

**Fonction** : `do_setusercontext()`
**Localisation** : bloc de traitement de `ChrootDirectory` (~ligne 1404)

**Diff complet** :
```diff
--- a/session.c
+++ b/session.c
@@ -1403,12 +1403,18 @@ do_setusercontext(struct passwd *pw)

        if (!in_chroot && options.chroot_directory != NULL &&
            strcasecmp(options.chroot_directory, "none") != 0) {
+               char *stripped_name;
                        tmp = tilde_expand_filename(options.chroot_directory,
                            pw->pw_uid);
                snprintf(uidstr, sizeof(uidstr), "%llu",
                    (unsigned long long)pw->pw_uid);
+               /* %w: username sans prefixe domaine (ex: "DOMAIN\user" -> "user") */
+               stripped_name = strchr(pw->pw_name, '\\');
+               stripped_name = (stripped_name != NULL) ?
+                   stripped_name + 1 : pw->pw_name;
                chroot_path = percent_expand(tmp, "h", pw->pw_dir,
-                   "u", pw->pw_name, "U", uidstr, (char *)NULL);
+                   "u", pw->pw_name, "U", uidstr,
+                   "w", stripped_name, (char *)NULL);
                safely_chroot(chroot_path, pw->pw_uid);
                free(tmp);
                free(chroot_path);
```

### Description technique

1. `strchr(pw->pw_name, '\\')` recherche le séparateur `\` dans le nom d'utilisateur
2. Si trouvé, `stripped_name` pointe sur le caractère suivant (le nom sans domaine)
3. Si absent (compte local), `stripped_name` est égal à `pw->pw_name` (comportement inchangé)
4. Le token `"w"` est passé à `percent_expand()` aux côtés des tokens existants `%u`, `%U`, `%h`

**Aucun autre fichier source n'est modifié.**
Les tokens existants `%u`, `%U`, `%h` sont **inchangés** et restent pleinement fonctionnels.

---

## 4. Analyse de sécurité

### Périmètre de la modification
- La modification est **strictement limitée** à la résolution du chemin `ChrootDirectory`
- Elle n'affecte **pas** le processus d'authentification
- Elle n'affecte **pas** les autorisations d'accès aux fichiers
- Elle n'affecte **pas** les autres directives de `sshd_config`

### Vecteurs d'attaque analysés

| Scénario | Analyse | Risque |
|----------|---------|--------|
| Traversée de répertoire via `%w` | `strchr` retourne un pointeur interne à `pw->pw_name`. Aucune allocation, aucune concaténation de chaîne non contrôlée. | Nul |
| Injection via nom d'utilisateur | `pw->pw_name` est fourni par le sous-système d'authentification Windows (Kerberos/NTLM). Il est validé en amont par le PAM Windows avant d'atteindre cette fonction. | Nul |
| Collision entre utilisateurs de domaines différents | Par conception : `frdom\T1234` et `pouet\T1234` aboutissent au même répertoire `E:\users\T1234`. Ce comportement est intentionnel et attendu — c'est l'objectif de la modification. L'accès reste contrôlé par les ACL NTFS du dossier. | Géré par ACL NTFS |
| Utilisateur sans domaine | Si `pw->pw_name` ne contient pas de `\`, `stripped_name = pw->pw_name` — comportement identique à `%u`. Rétrocompatible. | Nul |
| Buffer overflow | `stripped_name` est un pointeur dans une zone mémoire déjà allouée et terminée par `\0`. Aucune nouvelle allocation. `percent_expand()` gère l'expansion dans un buffer contrôlé (utilisé dans tout OpenSSH). | Nul |

### Isolation garantie par ChrootDirectory
Le mécanisme `ChrootDirectory` d'OpenSSH sur Windows restreint la racine visible
du client SFTP au dossier spécifié. L'utilisateur ne peut pas naviguer en dehors
de ce répertoire, quelle que soit la valeur résolue par `%w`.

---

## 5. Base de code et processus de build

### Version de base
- **Dépôt** : https://github.com/PowerShell/openssh-portable
- **Tag** : `v8.1.0.0` (correspondant à la version en production)
- **Commit de base** : identique à la release `v8.1.0.0p1-Beta` de Win32-OpenSSH

### Adaptations de compilation uniquement (non fonctionnelles)
Pour compiler avec Visual Studio 2022 (v18) et Windows SDK 10.0.22621.0
au lieu du SDK 8.1 d'origine, deux fichiers de build ont été mis à jour :

| Fichier | Modification |
|---------|-------------|
| `contrib/win32/openssh/paths.targets` | SDK `8.1` → `10.0.22621.0`, ZLib `2.1.11` → `1.3.1` (version inexistante corrigée) |
| `contrib/win32/openssh/*.vcxproj` (×22) | PlatformToolset `v140`/`v141` → `v145` |

Deux headers win32compat ont reçu une inclusion anticipée pour éviter
des conflits de déclaration entre le SDK 10.0 et les macros de compatibilité POSIX :

| Fichier | Ajout |
|---------|-------|
| `contrib/win32/win32compat/inc/unistd.h` | `#include <io.h>` en tête |
| `contrib/win32/win32compat/inc/fcntl.h` | `#include <io.h>` en tête |
| `contrib/win32/win32compat/inc/sys/stat.h` | `#include <direct.h>` en tête |

Ces trois ajouts forcent l'inclusion des headers système Windows **avant** que
les macros de substitution POSIX (`#define open`, `#define isatty`, `#define mkdir`)
ne soient définies, évitant ainsi des redéclarations ambiguës. Ils n'ont aucun
impact fonctionnel sur le comportement d'OpenSSH.

### Environnement de build
- Visual Studio 2022 (v18 Community)
- Windows SDK 10.0.22621.0
- MSVC v145
- LibreSSL 2.9.2.1 (fourni par le dépôt PowerShell/LibreSSL, linkage statique)
- ZLib 1.3.1 (fourni par le dépôt PowerShell/ZLib, linkage statique)

### Résultat du build
```
La génération a réussi.
4 Avertissement(s)  — dépréciations POSIX non bloquantes
0 Erreur(s)
```

**Binaire produit** : `sshd.exe` (1 164 288 octets)
**DLLs requises** : aucune supplémentaire (LibreSSL et ZLib en linkage statique)

---

## 6. Tests réalisés

Les tests ont été réalisés sur la machine de build (Windows 10.0.26200) avec
le binaire compilé.

### Test 1 — Validation de la configuration
```
sshd.exe -T -f sshd_config
```
→ `chrootdirectory E:\users\%w` correctement parsé, aucune erreur.

### Test 2 — Démarrage du démon
```
sshd.exe -d -f sshd_config
```
→ `Server listening on 127.0.0.1 port 2222` — démarrage nominal.

### Test 3 — Connexion SSH et résolution `%w`
- Connexion avec compte `DESKTOP\admin` (format `DOMAINE\utilisateur`)
- Commande `whoami` → retourne `desktop\admin` ✓
- Log sshd : `Changed root directory to "E:\test\chroot\admin"` ✓

Le domaine `DESKTOP\` a été strippé, seul `admin` est retenu.

### Test 4 — SFTP complet (upload / download)
```
sftp> pwd          → /
sftp> ls /         → /files
sftp> put fichier /files/fichier.txt   → OK
sftp> get /files/fichier.txt           → OK
```
Vérification physique : fichier présent dans `E:\test\chroot\admin\files\` ✓

### Test 5 — Rétrocompatibilité `%u`
Le token `%u` testé séparément retourne toujours `DOMAINE\utilisateur` sans modification.

---

## 7. Déploiement

### Fichier à remplacer en production
| Fichier | Action |
|---------|--------|
| `sshd.exe` | Remplacer par le binaire compilé |

Aucun autre fichier à modifier. L'architecture v8.1 est monolithique
(`sshd.exe` unique, sans `sshd-auth.exe` ni `sshd-session.exe`).

### Modification `sshd_config`
```diff
- ChrootDirectory E:\%u
+ ChrootDirectory E:\users\%w
```

### Migration des dossiers
```
E:\frdom\T1234  →  E:\users\T1234
E:\frdom\T5678  →  E:\users\T5678
...
```

### Procédure
1. Arrêter le service `sshd`
2. Sauvegarder `sshd.exe` en place
3. Copier le nouveau `sshd.exe`
4. Mettre à jour `sshd_config`
5. Migrer les dossiers utilisateurs
6. Redémarrer le service `sshd`
7. Valider avec un compte de chaque domaine (`frdom` et `pouet`)

---

## 8. Fichiers joints

| Fichier | Description |
|---------|-------------|
| `sshd.exe` | Binaire compilé à déployer |
| `session.c.patch` | Diff de la modification fonctionnelle |
| `README-cyber.md` | Ce document |

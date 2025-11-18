# Supervision DokuWiki — Application pédagogique

## Description

Cette application est un **outil de supervision inspiré de Nagios**, conçu pour surveiller un serveur **DokuWiki**. Elle est destinée à un usage pédagogique pour les étudiants en BTS SIO (option Systèmes & Réseaux).  

Elle fournit :
- Un **tableau de bord de supervision** (`supervision.php`) affichant l’état des services et fichiers critiques.
- Une **gestion des utilisateurs** avec rôles (`admin`, `superadmin`) et authentification sécurisée.
- Une **traçabilité** des connexions et actions via un journal d’événements (`journal.php`).
- Des **contrôles de sécurité** (CSRF, TOTP, rate-limit, cookies sécurisés, headers HTTPS/HSTS).

L’application est **déployée sous PHP** avec base SQLite côté serveur et fonctionne avec un seul fichier HTML/JS pour le support pédagogique.

---

## Arborescence & composants clés

Extrait de la structure :

nagios/ ├── config/ │   ├── config.php                 # Configuration globale (chemins, options sécurité) │   └── init_db.php                # Initialisation SQLite (tables + superadmin) ├── includes/ │   ├── db.php                     # Connexion PDO SQLite │   ├── auth.php                   # Sessions, rôles, gardes, CSRF │   ├── functions.php              # Utilitaires (logs, helpers) │   ├── totp.php                   # Génération/validation TOTP (RFC 6238) │   └── checks.php                 # Contrôles de supervision DokuWiki ├── public/ │   ├── index.php                  # Redirection login / supervision │   ├── login.php                  # Connexion + TOTP │   ├── logout.php                 # Déconnexion │   ├── totp_setup.php             # Configuration TOTP initiale │   ├── force_change_password.php  # Changement obligatoire mot de passe │   ├── supervision.php            # Tableau de bord │   ├── admin_users.php            # Gestion utilisateurs (RBAC) │   ├── journal.php                # Journal des accès │   └── css/ │       └── styles.css             # Styles front-end ├── sqlite/ │   └── supervision.sqlite         # Base SQLite principale └── logs/ └── journal.log                # Journal des accès

- Les données sensibles (hashs de mots de passe, secrets TOTP) sont **stockées dans SQLite** avec droits d’accès restreints.
- Les **sessions PHP** et cookies sécurisés gèrent l’état utilisateur.

---

## Schéma applicatif (simplifié)

Client / Navigateur │ POST login + TOTP ▼ Nginx / Apache (HTTPS, headers HSTS) │ Application PHP (public/.php → includes/.php) │ ├─ auth.php, totp.php, functions.php │ └─ force_change_password.php ▼ SQLite (supervision.sqlite, rate.sqlite) │ Logs / Nagios (app.log, journal)

### Flux d’authentification

1. POST `/login` → vérification mot de passe (`password_verify`)  
2. Si rôle admin → TOTP (`totp_verify`)  
3. Démarrage session PHP sécurisée (`session_start`, cookie HttpOnly + SameSite)  
4. Échecs → journalisation dans `rate.sqlite` et message affiché

### Changement de mot de passe forcé

1. Après login, si `force_password_change = 1` → redirection vers `force_change_password.php`  
2. Saisie du nouveau mot de passe (x2) + vérification CSRF et robustesse  
3. Mise à jour du hash dans SQLite, flag remis à 0, `log_event()`  
4. Redirection vers `supervision.php`

---

## Points pédagogiques

- Importance de **mots de passe forts** (ex: Argon2id)
- **Blocage automatique** après plusieurs échecs (protection brute force)
- Sécurité des sessions (`HttpOnly`, `SameSite`) et protection CSRF
- Lecture du journal pour surveiller les tentatives d’accès
- TP réseau : forcer **HTTPS**, headers sécurisés, audit des logs

### Exercice complémentaire

- Activer `force_password_change` pour un utilisateur, se connecter et effectuer le changement imposé pour comprendre la **traçabilité et le cycle de vie des mots de passe**.

---

## Fiches rapides

- **start_secure_session()**  
  Vérifie `session_status()`, définit `session_name()`, `session_set_cookie_params()` (httponly, secure, samesite), puis `session_start()`.
- **TOTP**  
  Code temporel partagé (30s step), vérification avec tolérance ±1 step.
- **force_change_password.php**  
  Accessible uniquement si flag `force_password_change=1` actif. Vérification mot de passe + CSRF → mise à jour SQLite → flag à 0 → log_event() → redirection.

---

## Suggestions d'améliorations

- Implémenter **alertes mail** pour warning/erreur  
- Ajouter onglet alertes dans le tableau de bord  
- Forcer HTTPS et refuser connexions non sécurisées  
- Externaliser les logs (ELK/Graylog) et anonymiser certaines données  
- Utiliser **CSP** pour réduire XSS  
- Ajouter **tests automatisés** (unitaires et intégration) sur auth et rate-limit

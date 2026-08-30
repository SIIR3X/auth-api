# Rapport de performance - base de données et API

Campagne du 15 septembre 2026, commit `3ac984d`. Données brutes :
[`data.md`](data.md) ; protocole et limites plus bas.

## Résumé

1. **Le nombre de comptes pèse peu sur les appels.** De 10 000 à 1 000 000 de
   comptes (base de 109 Mo à 10,5 Go), le débit maximal des appels authentifiés
   baisse de 2 à 10 % et leur latence p95 à charge égale ne bouge pas
   (1,6 → 1,8 ms à 16 clients sur `GET /users/me`). Toutes les requêtes du
   chemin chaud restent des parcours d'index : 0,01 à 0,04 ms côté base à
   1 million de comptes.
2. **Le composant limitant est le CPU de l'API, pas la base.** Sur les lectures
   authentifiées, l'API sature ses 3 cœurs dès 16 clients (11 000 à 14 000 req/s)
   pendant que PostgreSQL n'utilise que 1,3 à 1,9 de ses 3 cœurs. Au-delà, les
   clients supplémentaires ne font qu'attendre : p95 de 1,8 ms à 16 clients,
   7 ms à 64, 23 ms à 256.
3. **Les connexions dimensionnent le service.** Argon2id fixe le débit de
   `login` et `register` à 33-38 req/s sur 3 cœurs (≈ 90 ms de calcul par hash).
   À 256 connexions simultanées, chacune attend 7 à 8 secondes. Ce calcul est
   bien isolé : dans le trafic mixte à 256 clients, le profil répond en 0,8 ms
   (p50) et le refresh en 4,1 ms pendant que les connexions attendent.
4. **Le refresh plafonne vers 5 000 req/s, limité par PostgreSQL** (2,5 à 2,6
   cœurs sur 3 : une transaction d'écriture avec commit synchrone par appel),
   quel que soit le volume.
5. **Seules les écritures se dégradent avec le volume.** À 1 million de comptes,
   la transaction d'une connexion perd 25 à 35 % de débit (6 422 → 4 805 tx/s à
   32 connexions, p99 8,2 → 11 ms) et lit 11 400 blocs par seconde sur disque :
   la base dépasse la mémoire qui lui est allouée et la mise à jour des index à
   clés aléatoires (hash de jeton, UUID) devient une affaire d'entrées-sorties.
6. **Deux corrections se dégagent** : la purge des sessions coûte 750 ms par lot
   de 5 000 lignes à 1 million de comptes (elle relit tout l'arriéré à chaque
   lot), et près de 900 Mo d'index jamais utilisés par l'application
   ralentissent chaque écriture.

## 1. Ce qui a été mesuré

**Question posée :** comment évoluent la base de données et les appels à l'API
quand le nombre de comptes augmente et quand la charge monte ?

Deux axes, croisés :

| Axe | Valeurs |
|-----|---------|
| Volume de données | 10 000, 100 000 et 1 000 000 de comptes, avec l'historique qu'un compte accumule |
| Charge | 1, 4, 16, 64 et 256 clients simultanés (HTTP) ; 1, 8 et 32 connexions (SQL) |

Trois familles de mesures à chaque volume :

1. **Les appels HTTP** de bout en bout, par scénario et en trafic mixte :
   débit, latences p50/p95/p99/max, erreurs, CPU consommé par chaque composant.
2. **Les requêtes de l'application** exécutées directement sur PostgreSQL via
   les fonctions du dépôt (le même SQL que l'API, en requêtes préparées) :
   débit et latence selon le nombre de connexions.
3. **L'état de la base** : plans d'exécution réels (`EXPLAIN ANALYZE, BUFFERS`),
   tailles des tables et index, statistiques `pg_stat_statements` pendant le
   trafic mixte, durée des lots de purge.

## 2. Protocole

### Machine et isolation

- Machine virtuelle QEMU, 8 vCPU (« QEMU Virtual CPU version 2.5+ »),
  23,4 Go de mémoire, disque SSD, Debian 13 (noyau 6.12).
- PostgreSQL 17.11, commit mesuré `3ac984d`.
- Campagne du 15 septembre 2026, de 09:52 à 11:18 ; peuplement compris
  (9 minutes pour passer de 100 000 à 1 000 000 de comptes).

Tout tourne sur la même machine virtuelle. Pour que les composants ne se volent
pas de temps CPU et que la consommation de chacun soit mesurable, chacun est
épinglé sur ses cœurs :

| Cœurs | Composant |
|-------|-----------|
| 0-2 | PostgreSQL |
| 3 | Redis et NATS |
| 4-6 | API (`auth-api`, build release) |
| 7 | Générateur de charge |

La consommation CPU de chaque composant est lue dans `/proc/stat` sur ses
cœurs pendant la fenêtre de mesure.

### Configuration

- **PostgreSQL 17** sur disque (SSD), avec la durabilité de production :
  `fsync`, `synchronous_commit` et `full_page_writes` activés.
  `shared_buffers=4GB`, `effective_cache_size=12GB`, `work_mem=16MB`,
  `random_page_cost=1.1`, `max_wal_size=8GB`, `pg_stat_statements` et
  `track_io_timing`.
- **Redis** sans persistance, **NATS** avec JetStream sur disque.
- **API** en build release, pool PostgreSQL de 32 connexions et pool Redis de
  32. **Argon2id aux paramètres de production** (64 Mio, 3 itérations,
  4 voies), limité aux 3 cœurs de l'API.
- Le **rate limiter reste actif** (son coût fait partie de chaque requête), mais
  ses plafonds sont relevés pour qu'il ne refuse rien. Le CAPTCHA est désactivé,
  le seuil de verrouillage relevé, et les journaux au niveau `warn`.
- Les e-mails partent vers un Mailpit local.

### Données

Le jeu de données est déterministe et grossit par paliers (les 100 000 comptes
contiennent les 10 000 premiers). Par compte :

| Donnée | Quantité |
|--------|----------|
| Sessions actives | 2 |
| Sessions expirées ou révoquées | 3 (au-delà du délai de purge) |
| Tentatives de connexion sur 90 jours | 10, dont 2 échecs |
| Entrées d'audit sur 25 jours | 15 |
| Jeton de vérification d'e-mail utilisé | 1 |
| TOTP et 10 codes de récupération | 1 compte sur 5 |
| Second facteur par e-mail | 1 compte sur 20 |
| Jeton de réinitialisation utilisé | 1 compte sur 10 |

À 1 000 000 de comptes : 5 millions de sessions, 10 millions de tentatives de
connexion et 15 millions d'entrées d'audit. Tous les comptes partagent un même
hash Argon2id calculé avec les paramètres de production : vérifier un mot de
passe coûte donc ce qu'il coûte en production.

### Générateur de charge

- **Boucle fermée** : chaque client virtuel envoie sa requête suivante dès que
  la précédente a répondu, sans pause. Le débit mesuré est donc le maximum que
  le système soutient à cette concurrence, et la latence est celle que voit un
  client qui attend. Ce n'est pas un test à débit imposé.
- **Jetons d'accès** : jusqu'à 100 000 jetons signés à l'avance pour des comptes
  tirés uniformément, ce qui rend réalistes les défauts du cache de validité des
  sessions.
- **Adresses clientes** : chaque requête vient d'une adresse tirée parmi
  262 144, pour que les budgets par adresse se comportent comme avec du vrai
  trafic.
- **Refresh** : chaque client virtuel se connecte une fois avant le chrono, puis
  suit sa propre chaîne de rotation.
- **Mesure** : 5 secondes de chauffe puis 20 secondes de mesure par point HTTP
  (3 + 10 secondes par point SQL). Redis est vidé avant chaque point HTTP.
  Latences dans un histogramme à 1 % de résolution.

### Scénarios HTTP

| Scénario | Appel | Ce qu'il sollicite |
|----------|-------|--------------------|
| `profile` | `GET /users/me` | Vérification du jeton (Redis), lecture du compte |
| `sessions` | `GET /users/me/sessions` | Sessions actives d'un compte |
| `audit` | `GET /users/me/audit?limit=50` | Historique, table partitionnée |
| `two_factor` | `GET /users/me/two-factor` | Seconds facteurs et codes restants |
| `refresh` | `POST /auth/refresh` | Rotation du refresh token (transaction), émission d'un jeton |
| `login` | `POST /auth/login` | Argon2id, compteurs anti-bruteforce, écritures de connexion |
| `register` | `POST /auth/register` | Argon2id, création du compte, e-mail |
| `mixed` | tous | 50 % refresh, 20 % profil, 10 % sessions, 5 % audit, 5 % 2FA, 8 % connexions, 2 % inscriptions |

La composition du trafic mixte reflète un service d'authentification réel :
les serveurs de ressources vérifient les jetons d'accès localement (JWKS), donc
l'API voit surtout des rafraîchissements, puis des pages de compte, puis des
connexions.

### Requêtes SQL mesurées

| Requête | Utilisée par |
|---------|--------------|
| Utilisateur par e-mail | Connexion |
| Session par refresh token | Refresh |
| Validité d'une session | Chaque requête authentifiée, sur défaut de cache |
| Sessions actives d'un compte | `GET /users/me/sessions` |
| Échecs récents par identifiant, par adresse | Connexion (anti-bruteforce) |
| Échecs consécutifs d'un compte | Connexion échouée (verrouillage) |
| Rôles et permissions | Émission de chaque jeton d'accès |
| Page d'historique | `GET /users/me/audit` |
| Seconds facteurs et codes | `GET /users/me/two-factor` |
| Écritures d'une connexion | Session, compte, tentative et audit en une transaction |

## 3. Résultats

### 3.1 Capacité à 1 million de comptes

| Appel | Débit maximal | Atteint dès | p95 à 16 clients | Composant limitant |
|-------|--------------:|------------:|-----------------:|--------------------|
| `GET /users/me` | 12 620 req/s | 16 clients | 1,8 ms | CPU de l'API (2,98 / 3 cœurs) |
| `GET /users/me/sessions` | 12 315 req/s | 16 clients | 1,8 ms | CPU de l'API |
| `GET /users/me/audit` | 11 745 req/s | 16 clients | 1,9 ms | CPU de l'API |
| `GET /users/me/two-factor` | 11 247 req/s | 16 clients | 1,9 ms | CPU de l'API |
| `POST /auth/refresh` | 5 055 req/s | 64 clients | 7,2 ms | PostgreSQL (2,6 / 3 cœurs) |
| `POST /auth/login` | 33 req/s | 4 clients | 517 ms | Argon2id (CPU de l'API) |
| `POST /auth/register` | 33 req/s | 4 clients | 549 ms | Argon2id (CPU de l'API) |
| Trafic mixte | 322 req/s | 4 clients | 468 ms | Argon2id (10 % du trafic) |

Aucune erreur sur les 120 points HTTP de la campagne, jusqu'à 256 clients
simultanés. Le générateur de charge n'a jamais dépassé 0,51 cœur : les plafonds
sont bien ceux du serveur.

Le trafic mixte plafonne bas parce qu'il est en boucle fermée : les 10 % de
connexions et d'inscriptions occupent les clients virtuels pendant des centaines
de millisecondes. Son intérêt est ailleurs : il montre que les appels rapides
ne sont pas pénalisés par les connexions en attente.

| Trafic mixte, 1M comptes, 256 clients | req/s | p50 | p95 |
|---------------------------------------|------:|----:|----:|
| refresh | 156 | 4,1 ms | 10,7 ms |
| profil | 66 | 0,81 ms | 5,6 ms |
| sessions | 31 | 0,87 ms | 5,7 ms |
| connexion | 27 | 7,7 s | 7,8 s |

### 3.2 Effet du nombre de comptes

![Débit selon le nombre de clients simultanés](img/http-throughput.svg)

| Mesure | 10 000 | 100 000 | 1 000 000 | Écart |
|--------|-------:|--------:|----------:|------:|
| Taille de la base | 109 Mo | 1,3 Go | 10,5 Go | ×97 |
| `GET /users/me`, débit maximal | 14 086 | 13 096 | 12 620 req/s | -10 % |
| `GET /users/me`, p95 à 16 clients | 1,6 ms | 1,7 ms | 1,8 ms | +0,2 ms |
| `GET /users/me/audit`, débit maximal | 12 306 | 12 067 | 11 745 req/s | -5 % |
| `POST /auth/refresh`, débit maximal | 5 139 | 5 324 | 5 055 req/s | -2 % |
| `POST /auth/login`, débit maximal | 38 | 34 | 33 req/s | -13 % |
| `POST /auth/login`, p50 à 1 client | 69 ms | 76 ms | 80 ms | +11 ms |
| Transaction de connexion, 32 connexions | 6 422 | 6 493 | 4 805 tx/s | -25 % |
| Transaction de connexion, p99 à 32 connexions | 8,2 ms | 8,0 ms | 11,0 ms | +2,8 ms |

Les lectures ne ralentissent presque pas : une recherche dans un index B-tree
coûte un niveau de plus quand la table est multipliée par cent, et les pages
utiles restent en mémoire (taux de cache de 99,8 à 100 % dès 16 clients).

Les écritures, elles, ralentissent à 1 million de comptes. Pendant le trafic
mixte, `pg_stat_statements` montre les insertions dans `sessions`,
`login_attempts` et `audit_log` passer de 0,1 ms à 0,4-0,56 ms en moyenne, avec
des lectures de blocs à chaque appel. La base (10,5 Go, dont 5,6 Go d'index)
dépasse les 4 Go de `shared_buffers`, et chaque insertion met à jour des index
dont les clés sont aléatoires (hash du jeton, UUID) : la page à modifier est
rarement en mémoire.

La baisse de débit des connexions (-13 %) ne vient pas de la base : PostgreSQL
n'y consomme que 0,1 cœur, et c'est le calcul Argon2id lui-même qui passe
d'environ 79 à 90 ms par hash. Hypothèse non vérifiée : Argon2id est limité par
la bande passante mémoire (64 Mio par hash), partagée dans la machine virtuelle
avec les 10 Go de cache de la base.

### 3.3 Effet de la charge

![Latence p95 selon le nombre de clients simultanés](img/http-p95.svg)

Chaque appel suit le même profil, quel que soit le volume :

- **Jusqu'au plafond**, le débit croît presque linéairement avec les clients et
  la latence reste stable (0,7 à 1,8 ms pour les lectures).
- **Au plafond**, le débit ne bouge plus et la latence croît proportionnellement
  au nombre de clients : chacun attend son tour. Pour les lectures, p95 passe de
  1,8 ms (16 clients) à 7 ms (64) puis 23 ms (256).
- **Aucun effondrement** : le débit à 256 clients est égal ou supérieur à celui
  de 64 clients, sans erreur ni délai d'expiration.

Pour les connexions, le plafond est atteint dès 4 clients (3 cœurs, 3 hash à la
fois) : p95 de 158 ms à 4 clients, 517 ms à 16, 2 s à 64 et 7,9 s à 256.

### 3.4 Où part le temps CPU

Coût moyen d'un appel au plafond, à 1 million de comptes (cœurs consommés divisés
par le débit) :

| Appel | API | PostgreSQL | Redis + NATS |
|-------|----:|-----------:|-------------:|
| `GET /users/me` | 0,24 ms | 0,12 ms | 0,05 ms |
| `GET /users/me/audit` | 0,25 ms | 0,15 ms | 0,05 ms |
| `GET /users/me/two-factor` | 0,26 ms | 0,16 ms | 0,05 ms |
| `POST /auth/refresh` | 0,44 ms | 0,51 ms | 0,06 ms |
| `POST /auth/login` | 90 ms | 3 ms | 0,3 ms |
| `POST /auth/register` | 93 ms | 3 ms | 0,3 ms |

Sur un appel authentifié, l'API dépense deux fois plus de CPU que la base : la
vérification de la signature ES256 du jeton, le rate limiter et la sérialisation
pèsent plus que la requête SQL. Un refresh est deux fois plus cher, réparti à
parts égales entre l'API (signature d'un nouveau jeton) et PostgreSQL (verrou de
la session, rotation, insertion, rôles et permissions en une transaction).

Répartition du temps SQL pendant le trafic mixte à 1 million de comptes :

| Requête | Part du temps SQL | Moyenne |
|---------|------------------:|--------:|
| Insertion de la session (refresh) | 15 % | 0,12 ms |
| Insertion de la session (connexion) | 13 % | 0,56 ms |
| Révocation de la session tournée | 12 % | 0,09 ms |
| Insertion dans `audit_log` | 11 % | 0,39 ms |
| Insertion dans `login_attempts` | 10 % | 0,43 ms |
| Rôles et permissions | 6 % | 0,04 ms |

Plus de 60 % du temps SQL part dans des écritures, alors qu'elles représentent
une minorité des appels.

### 3.5 Base de données

![Latence p99 des requêtes de l'application](img/db-p99.svg)

**Toutes les requêtes du chemin chaud utilisent un index à tous les volumes**
(plans dans [`data.md`](data.md#plans-dexécution)) : 0,01 à 0,04 ms d'exécution
à 1 million de comptes, sans lecture disque. Depuis l'application, une requête
coûte 0,16 à 0,32 ms (p50, une connexion), aller-retour et préparation inclus,
et reste sous 0,65 ms au p99 à 8 connexions (0,94 ms pour les seconds facteurs,
qui font deux requêtes), identique à 10 000 et à 1 million de comptes.

![Débit des requêtes selon le nombre de connexions](img/db-throughput.svg)

Les débits de lecture de ce graphique **sous-estiment PostgreSQL** : dès
8 connexions, le générateur de charge sature son cœur (1,00) alors que PostgreSQL
n'utilise que 1,6 à 2,1 de ses 3 cœurs. Les 19 000 à 28 000 requêtes par seconde
mesurées sont un minimum. La transaction d'écriture, elle, n'est pas bornée par
le client (0,3 à 0,7 cœur) : sa baisse à 1 million de comptes est réelle.

Les mesures à une connexion du palier 1M ont été prises juste après le
peuplement, cache froid : elles montrent des lectures disque (jusqu'à 375 ms
d'entrées-sorties par seconde pour la page d'historique) qui disparaissent aux
points suivants.

Ce que coûte le volume en stockage :

| Table | Lignes à 1M | Table | Index |
|-------|------------:|------:|------:|
| `audit_log` | 15,3 M | 1,5 Go | 2,4 Go |
| `sessions` | 6,0 M | 1,4 Go | 1,5 Go |
| `login_attempts` | 10,3 M | 1,1 Go | 1,1 Go |
| `recovery_codes` | 2,0 M | 226 Mo | 443 Mo |
| `users` | 1,0 M | 225 Mo | 158 Mo |

Soit environ 10 Ko par compte, index compris, dont la moitié en index.

**Index jamais parcourus pendant toute la campagne**, à 1 million de comptes :

| Index | Taille | Utilité |
|-------|-------:|---------|
| `audit_log_*_request_id_created_at_idx` | 755 Mo | Seul `audit::find_by_request_id` s'en sert, et aucune route ne l'appelle |
| `login_attempts_pkey` | 403 Mo | Conservé volontairement (réplication logique) |
| `idx_sessions_family_created` | 330 Mo | Utile : révocation d'une famille sur rejeu, non exercée ici |
| `recovery_codes_code_hash_key` | 147 Mo | Utile : connexion par code de récupération, non exercée ici |
| `idx_sessions_family_active` | 118 Mo | **Inutilisable** : la révocation filtre sur `revoked_at IS NULL OR compromised_at IS NULL OR ...`, que cet index partiel ne peut pas servir |

### 3.6 Purge

| Tâche (lots de 5 000 lignes) | 10k | 100k | 1M |
|------------------------------|----:|-----:|---:|
| Sessions expirées ou révoquées | 27-66 ms | 128-269 ms | 738-2 329 ms |
| Tentatives de connexion (lot vide) | 9 ms | 93 ms | 832 ms |
| Jetons de vérification et de réinitialisation | 9-16 ms | 7-16 ms | 9-16 ms |

Le coût d'un lot de sessions croît avec l'arriéré et non avec la taille du lot :
`cleanup_expired_sessions` sélectionne les candidats avec un `UNION` suivi d'un
`LIMIT`, et le dédoublonnage oblige PostgreSQL à lire tous les candidats (3
millions à 1M comptes) avant d'en garder 5 000. À ce rythme, résorber un arriéré
de 3 millions de sessions prend plus de 7 minutes de suppression continue.

Le lot vide de `login_attempts` (832 ms) vient en partie du jeu de données :
les lignes ont été insérées par compte et non dans l'ordre chronologique, ce qui
rend l'index BRIN sur `attempted_at` inefficace. En production, les tentatives
arrivent dans l'ordre et le BRIN reste sélectif ; il faut en revanche le
vérifier après tout import de données en masse.

## 4. Capacité estimée

À partir des débits mesurés sur 3 cœurs d'API, pour un service de 1 million de
comptes. Les hypothèses de trafic sont des ordres de grandeur, à remplacer par
les vôtres :

| Hypothèse | Trafic de pointe | Capacité mesurée | Marge |
|-----------|-----------------:|-----------------:|------:|
| 50 000 utilisateurs actifs en même temps, un refresh toutes les 15 minutes | 56 refresh/s | 5 055 req/s | ×90 |
| Chacun charge 20 pages de compte par heure | 280 req/s | 11 000-12 600 req/s | ×40 |
| 20 % des comptes se connectent dans l'heure de pointe | 56 connexions/s | 33 req/s | **×0,6** |

Les appels authentifiés et le refresh laissent une marge considérable. **Les
connexions sont le premier point de saturation** : une pointe de 56 connexions
par seconde demande environ 5 cœurs d'API avec les paramètres Argon2id actuels,
soit deux instances de la taille mesurée pour garder une marge. L'API étant sans état, cela se règle
en ajoutant des instances ; chaque cœur ajouté apporte 11 à 13 connexions par
seconde et consomme 64 Mio de mémoire par hash en cours.

## 5. Recommandations

Par ordre d'impact :

1. **Dimensionner l'API sur les connexions, pas sur les requêtes.** Compter
   11 à 13 connexions par seconde par cœur, `ARGON2_MAX_CONCURRENCY` égal au
   nombre de cœurs et 64 Mio de mémoire par cœur pour Argon2id. Surveiller
   `argon2_queue_available_permits` : à 0 de façon prolongée, les connexions
   s'accumulent et il faut une instance de plus.
2. **Borner le coût d'un lot de purge des sessions.** Remplacer le `UNION ... LIMIT`
   de `cleanup_expired_sessions` par deux suppressions bornées indépendantes
   (sessions expirées, puis révoquées), chacune avec son propre `LIMIT`, dans une
   nouvelle migration. Le coût d'un lot redevient proportionnel au lot.
3. **Supprimer `idx_sessions_family_active`** (118 Mo à 1M, inutilisable), et
   décider du sort de l'index `request_id` de l'audit (755 Mo à 1M, aucune route
   ne s'en sert) : le garder seulement si le support recherche l'audit par
   identifiant de requête. Chaque index retiré allège toutes les insertions.
4. **Au-delà du million de comptes, donner à PostgreSQL la mémoire de ses index
   d'écriture.** C'est le seul chemin qui se dégrade avec le volume. À 1M,
   les index de `sessions`, `login_attempts` et `audit_log` pèsent 5 Go : viser
   une mémoire (`shared_buffers` et cache du système) qui les contient, ou
   réduire les durées de rétention (90 jours de tentatives, 12 mois d'audit) qui
   font grossir ces tables.
5. **Priorité basse :** la page d'historique parcourt aussi les 12 partitions
   mensuelles futures, vides (0,04 ms au total aujourd'hui) ; borner la requête
   à `created_at <= now()` permettrait de les écarter. Le refresh, limité par
   PostgreSQL, garde une marge de ×90 sur l'hypothèse de trafic : inutile de
   l'optimiser pour l'instant.

## Limites de la mesure

- **Une seule machine virtuelle** : le générateur de charge, l'API et la base
  partagent le même hôte, épinglés sur des cœurs distincts. Il n'y a ni latence
  réseau, ni TLS, ni Nginx entre le client et l'API : en production, chaque appel
  coûte en plus un aller-retour réseau et le chiffrement.
- **Générateur sur un cœur** : sa consommation est mesurée à chaque point. En
  HTTP, elle n'a jamais dépassé 0,51 cœur. Dans le benchmark SQL, elle atteint
  1 cœur dès 8 connexions sur les lectures : ces débits-là sont des minimums
  (voir 3.5).
- **Boucle fermée** : les latences à forte charge sont celles d'un client qui
  attend son tour. Un trafic ouvert (des utilisateurs qui arrivent sans attendre
  les autres) produit des files plus longues une fois la saturation atteinte.
- **Données synthétiques et uniformes** : pas de comptes « chauds » ; tous les
  comptes ont le même profil d'historique.
- **Volumes cumulés** : les scénarios d'écriture d'un palier (connexions,
  inscriptions, transactions de connexion) ajoutent des lignes au palier suivant ;
  c'est négligeable devant les volumes.
- **Machine virtuelle QEMU** : la performance absolue dépend de l'hôte. Ce sont
  les tendances (évolution avec le volume, point de saturation, composant
  limitant) qui se transposent, pas les chiffres bruts.

## Reproduire

```bash
make perf                                   # la campagne, plusieurs heures
make perf-report RUN=reports/perf/<run>     # tableaux et graphiques dans docs/perf/
```

Le protocole et les variables sont décrits dans [`perf/README.md`](../../perf/README.md).
Toutes les données brutes de ce rapport sont dans [`data.md`](data.md).

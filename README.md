# ARCHIPEL - Protocole P2P decentralise et chiffre

## 1. Contexte et mission
Archipel est un protocole de communication Peer-to-Peer (P2P) concu pour fonctionner sans Internet, sans serveur central et sans autorite de certification. Le but est de survivre a une coupure totale d'infrastructure en creant un reseau local souverain ou chaque noeud est a la fois client et serveur.

Contrainte absolue: zero connexion Internet pendant la demo (hors module Gemini, isolable et desactivable).

## 2. Choix technologiques (Sprint 0)

### Langage principal: Python 3.10+
- Rapidite de prototypage pour tenir les sprints du hackathon.
- `asyncio` pour gerer decouverte UDP, TCP, et CLI sans blocage.
- Ecosysteme crypto mature (`PyNaCl`, et extension possible `PyCryptodome`).

### Transport reseau retenu
- Decouverte de pairs: UDP Multicast (`239.255.42.99:6000`).
- Transfert de donnees: TCP sockets (port par defaut `7777`).
- Justification: stack simple, eprouvee, et adaptee au delai de 24h.

### Segmentation (chunking)
- Taille de chunk cible: `512 KB`.
- Objectif: transfert robuste, verification d'integrite par bloc, reprise en cas de panne pair.

## 3. Specification paquet Archipel v1
Format binaire de base:

| Champ | Taille | Description |
| :--- | :--- | :--- |
| `MAGIC` | 4 octets | Signature protocole (`ARCH`) |
| `TYPE` | 1 octet | Type de paquet |
| `NODE_ID` | 32 octets | Cle publique Ed25519 (identifiant noeud) |
| `PAYLOAD_LEN` | 4 octets | Longueur payload (`uint32` Big Endian) |
| `PAYLOAD` | Variable | Donnees (chiffrees en sprint 2) |
| `HMAC-SHA256` | 32 octets | Integrite du paquet |

Types de paquets:
- `0x01 HELLO`
- `0x02 PEER_LIST`
- `0x03 MSG`
- `0x04 CHUNK_REQ`
- `0x05 CHUNK_DATA`
- `0x06 MANIFEST`
- `0x07 ACK`

## 4. Securite et cryptographie
- Identite noeud: paire Ed25519 (generee localement).
- E2E cible: X25519 (ECDH) + AES-256-GCM (Sprint 2).
- Integrite paquet: HMAC-SHA256.
- Authentification sans CA: TOFU / Web of Trust.
- Regles anti-pattern:
- pas de cle privee en dur dans le code ou le repo
- pas d'algorithme crypto maison
- pas de reutilisation de nonce avec la meme cle

## 5. Schema architecture (Sprint 0)
```text
+-----------------------+            +-----------------------+
| Node A                |            | Node B                |
| - UDP discovery       |<---------->| - UDP discovery       |
| - TCP server/client   |            | - TCP server/client   |
| - Crypto identity     |            | - Crypto identity     |
+-----------------------+            +-----------------------+
            \                               /
             \-----------+-----------------/
                         |
                +-----------------------+
                | Node C                |
                | - Peer table          |
                | - Chunk storage       |
                +-----------------------+
```

## 6. Etat actuel du repository
Structure actuelle:
```text
src/
|-- crypto/      # PKI (Ed25519), derivation de session
|-- network/     # constants, packet, peer table
|-- transfer/    # chunking, manifest
|-- messaging/   # service messaging (placeholder)
`-- cli/         # CLI de demo
docs/
|-- protocol-spec.md
`-- architecture.md
tests/
demo/
```

## 7. Commandes utiles
Generation des cles:
```bash
python sprintO.py keygen --node node-1 --out keys
# ou via variable d'environnement:
# $env:ARCHIPEL_KEY_PASSWORD="MotDePasseFort123!"
# python sprintO.py keygen --node node-1 --out keys --password-env ARCHIPEL_KEY_PASSWORD
```

Aide CLI:
```bash
python -m src.cli.main --help
```

Exemples de commandes CLI:
```bash
python -m src.cli.main start --port 7777
python -m src.cli.main peers
python -m src.cli.main msg <node_id> "Hello"
python -m src.cli.main send <node_id> <filepath>
python -m src.cli.main receive
python -m src.cli.main download <file_id>
python -m src.cli.main status
python -m src.cli.main trust <node_id>
python -m src.cli.main keygen
```

## 8. Checklist Sprint 0
- [x] Choix du langage et justification documentes
- [x] Choix transport local documente (UDP multicast + TCP)
- [x] Format de paquet defini (header + payload + HMAC)
- [x] Schema architecture ajoute dans le README
- [x] Generation de cles Ed25519 operationnelle (`keygen.py`)
- [ ] Repository Git initialise et workflow applique (`main`, `develop`, `feature/*`)
- [ ] Premier commit tague `sprint-0`
- [ ] Tous les membres connectes au meme repo (organisation equipe)

## 9. Roadmap des sprints suivants
- Sprint 1: decouverte UDP reelle + peer table live + serveur TCP.
- Sprint 2: handshake, chiffrement E2E, authentification TOFU.
- Sprint 3: manifest, chunking, telechargement parallele multi-noeuds.
- Sprint 4: integration CLI de demo complete + README final jury.

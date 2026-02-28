# Checklist Demo Jury - Sprint 4

## 1. Machine fraiche (validation)
- [ ] `git clone` du repo
- [ ] `pip install -r requirements.txt`
- [ ] `python -m src.cli.main keygen`
- [ ] `python -m src.cli.main start --port 7777 --no-ai`

## 2. Test P2P sans interface
- [ ] Message P2P A -> B:
- [ ] `python -m src.cli.main msg dummy "hello p2p" --ip <IP_B> --port 7777`
- [ ] Fichier 50 MB A -> B:
- [ ] generer fichier test puis `python -m src.cli.main send <fichier> --ip <IP_B> --port 7777`
- [ ] verifier reception dans `downloads/` cote B

## 3. Demo jury (scenario court)
- [ ] Lancer 2 noeuds
- [ ] Montrer message chiffre en CLI
- [ ] Montrer transfert 50 MB et verification d'integrite

## 4. Backup panne reseau
- [ ] basculer sur hotspot local dedie
- [ ] utiliser IP manuelle si discovery KO
- [ ] conserver un fichier test local deja pret

## 5. Securite (must-have)
- [ ] aucune cle privee dans le repo
- [ ] primitives crypto standards uniquement
- [ ] nonces et cles de session jamais reutilises

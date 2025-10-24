# 🧠 TP3 – Cryptographie en Java  
**Thème : Chiffrement, Signature numérique et Certificats numériques**

---

## 🎯 Objectif du TP
Ce projet Java démontre l’utilisation de la **cryptographie symétrique**, **asymétrique**, la **génération de certificats** et la **signature HMAC**.  
Il s’agit du **TP3** du module *Sécurité & Cryptographie*, réalisé avec **IntelliJ IDEA** et **Java 21**.

---

## 🗂️ Structure du projet

tpcrypto/
├─ certs/ # Dossier des clés et certificats
│ ├─ devoir.jks # Keystore Java (contient la clé privée)
│ └─ certificate.cert # Certificat public (X.509)
├─ src/ # Code source Java
│ ├─ AESCrypto.java # Chiffrement RSA (public/private)
│ ├─ RSACrypto.java # Chiffrement hybride RSA + AES
│ ├─ HmacSign.java # Génération de signature HMAC-SHA256
│ ├─ HmacVerify.java # Vérification d’intégrité HMAC
│ └─ Main.java # Programme principal (tests)
└─ README.md

yaml
Copy code

---

## ⚙️ Prérequis
- **Java JDK 17+** (testé avec 21)
- **IntelliJ IDEA** ou tout IDE Java
- Commande `keytool` (inclus avec le JDK)

---

## 🔑 Génération des clés et certificats

Dans le dossier du projet (`tpcrypto`), exécutez ces commandes PowerShell :

```powershell
New-Item -ItemType Directory -Force -Path certs | Out-Null

& "C:\Users\<USERNAME>\.jdks\ms-21.0.8\bin\keytool.exe" -genkeypair `
  -alias devoir -keyalg RSA -keysize 2048 -validity 365 `
  -keystore "certs\devoir.jks" -storepass 123456 -keypass 123456 `
  -dname "CN=Etudiant, OU=Classe LIA, O=Ecole, L=Casa, ST=Casa, C=MA"

& "C:\Users\<USERNAME>\.jdks\ms-21.0.8\bin\keytool.exe" -exportcert `
  -alias devoir -keystore "certs\devoir.jks" -storepass 123456 `
  -rfc -file "certs\certificate.cert"
🚀 Exécution du projet
Option 1 – Depuis IntelliJ
Ouvrir le projet.

Vérifier que la Working Directory = $ProjectFileDir$.

Lancer Main.java ▶️

Option 2 – Depuis le terminal
powershell
Copy code
javac -d out src\*.java
java -cp out Main
🧩 Fonctionnalités
🔐 Partie 1 – RSA (AESCrypto.java)
Charge la clé publique depuis certificate.cert.

Chiffre le message avec RSA.

Déchiffre avec la clé privée du keystore.

🧬 Partie 2 – RSA + AES (RSACrypto.java)
Génère une clé AES aléatoire.

Chiffre le texte en AES/GCM.

Chiffre la clé AES avec la clé publique RSA.

Déchiffre la clé AES via la clé privée RSA, puis déchiffre le message.

🧾 Partie 3 – Signature HMAC
HmacSign.java crée une signature SHA-256 basée sur une clé secrète.

HmacVerify.java compare et valide l’intégrité du message signé.

🧠 Exemple de sortie
csharp
Copy code
Partie 2: AESCrypto (RSA public/private)
[AESCrypto] Encrypted (Base64): MIIByjQ...
[AESCrypto] Decrypted: Bonjour tout le monde

Partie 3: RSACrypto (RSA + AES Hybrid)
[RSACrypto] Hybrid (Base64): e8yVv2m...
[RSACrypto] Decrypted: Bonjour tout le monde

Partie 4 & 5: HMAC Signature & Vérification
Signature HMAC (Base64): dX+EfwxNjX9k2sO9...
Vérification: INTÈGRE ✅
💡 Remarques
Les mots de passe sont 123456 pour le keystore et la clé.

L’alias utilisé est devoir.

Le projet utilise les classes Java standards :

Cipher, KeyStore, CertificateFactory

Mac, SecretKeySpec, Base64

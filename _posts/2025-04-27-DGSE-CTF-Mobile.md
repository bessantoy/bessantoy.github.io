---
title: DGSE CTF - Mission 5 (Mobile)
date: 2025-04-27 14:30:00 +0800
categories: [DGSE CTF]
tags: [dgse, rootme, mobile]
image:
  path: /assets/img/20250427/mission-05-statement.png
  alt: Brief de la mission 5.
---

## 🔍 Reconnaissance 

L'application se présente de la manière suivante :
- Une section `Messages on previous devices` contenant des messages chiffrés, probablement avec les identifiants d'un ancien appareil.
- Une section `Messages on this device` affichant les messages en clair destinés à l'appareil actuel.

![Desktop View](/assets/img/20250427/mission-05-app-previous.png)
_Liste des messages chiffrés_

![Desktop View](/assets/img/20250427/mission-05-app-current.png)
_Liste des messages en clair_

## 🌐 Interception du traffic HTTP

Avant de passer à la décompilation de l'APK, j’ai commencé par intercepter le trafic HTTP via un proxy avec Burp Suite. Voici le guide proposé par PortSwigger pour configurer un appareil Android avec Burp : [**Configuring an Android device to work with Burp Suite**][burpsuite]

[burpsuite]: https://portswigger.net/burp/documentation/desktop/mobile/config-android-device

Voici la requête intéressante que j'ai intercepté : 

![Desktop View](/assets/img/20250427/mission-05-burpsuite.png)
_Interception du traffic HTTP avec Burpsuite_

On peut voir que l'application envoie une requête GET à `/messages` avec un paramètre `id=5vmObbpVKWesTEbiSxlCzXSEXFUwues1nVIGiMYOED8=`.
En réponse, on obtient une liste de messages, chacun contenant :
- `content` : le contenu du message
- `isEncrypted` : un booléen indiquant si le message est chiffré
- `sender`: l'éxpéditeur
- `timestamp`: la date d'envoi

Ce qu’on observe ici, c’est que tous les messages renvoyés par l’API sont chiffrés, alors que certains apparaissent en clair dans l’application. Cela suggère que le déchiffrement est effectué localement, dans l'application elle-même, avant l'affichage.

## 🧩 Reverse de l'APK

On peut décompiler l'APK grâce à un outil comme **jadx** ou directement avec **androidstudio**.
En fouillant un peu, on tombe sur méthode `decryptMessage` très intéréssante dans `smali\out\com\nullvastation\cryssage\ui\home\HomeViewModel.smali` : 

```bash
.method private final decryptMessage(Ljava/lang/String;)Ljava/lang/String;
    .registers 8

    .line 73
    :try_start_0
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    const-string v1, "MODEL"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Landroid/os/Build;->BRAND:Ljava/lang/String;

    const-string v2, "BRAND"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, v0, v1}, Lcom/nullvastation/cryssage/ui/home/HomeViewModel;->hashDeviceId(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 74
    const-string v1, "s3cr3t_s@lt"

    invoke-direct {p0, v0, v1}, Lcom/nullvastation/cryssage/ui/home/HomeViewModel;->deriveKey(Ljava/lang/String;Ljava/lang/String;)[B

    move-result-object v0

    .line 75
    const-string v1, "LJo+0sanl6E3cvCHCRwyIg=="

    const/4 v2, 0x0

    invoke-static {v1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v1

    .line 77
    const-string v3, "AES/CBC/PKCS5Padding"

    invoke-static {v3}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object v3

    .line 78
    new-instance v4, Ljavax/crypto/spec/SecretKeySpec;

    const-string v5, "AES"

    invoke-direct {v4, v0, v5}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 79
    new-instance v0, Ljavax/crypto/spec/IvParameterSpec;

    invoke-direct {v0, v1}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 80
    check-cast v4, Ljava/security/Key;

    check-cast v0, Ljava/security/spec/AlgorithmParameterSpec;

    const/4 v1, 0x2

    invoke-virtual {v3, v1, v4, v0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 82
    invoke-static {p1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p1

    .line 83
    invoke-virtual {v3, p1}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object p1

    .line 84
    invoke-static {p1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNull(Ljava/lang/Object;)V

    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    const-string v1, "UTF_8"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/lang/String;

    invoke-direct {v1, p1, v0}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V
    :try_end_50
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_50} :catch_51

    return-object v1

    :catch_51
    move-exception p1

    .line 86
    const-string v0, "Error decrypting message"

    check-cast p1, Ljava/lang/Throwable;

    const-string v1, "DECRYPT_ERROR"

    invoke-static {v1, v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 87
    const-string p1, "[Encrypted] This message was encrypted with old device credentials"

    return-object p1
.end method
```
Cette méthode implémente un déchiffrement AES en mode CBC avec un padding PKCS5. Voici ce qu’elle fait :
- Récupère les valeurs MODEL et BRAND du téléphone.
- Concatène ces deux valeurs pour former un identifiant unique d’appareil.
- Dérive une clé AES à partir de cet identifiant et d’un sel fixe (`s3cr3t_s@lt`).
- Utilise un IV fixe (`LJo+0sanl6E3cvCHCRwyIg==`, encodé en Base64).
- Déchiffre le message passé en argument (lui aussi encodé en Base64).

Si le déchiffrement échoue (par exemple si le message a été chiffré avec un autre appareil), l’application retourne ce message par défaut :
`[Encrypted] This message was encrypted with old device credentials`

Voici également la méthode `deriveKey` utilisée pour générer la clé AES :

```bash
.method private final deriveKey(Ljava/lang/String;Ljava/lang/String;)[B
    .registers 5

    .line 66
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const/16 v0, 0x3a

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    .line 67
    const-string p2, "SHA-256"

    invoke-static {p2}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object p2

    .line 68
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    const-string v1, "UTF_8"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object p1

    const-string v0, "this as java.lang.String).getBytes(charset)"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object p1

    const-string p2, "digest(...)"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method
```

Cette fonction concatène l’identifiant d’appareil avec le sel, puis calcule le SHA-256 de la chaîne résultante pour produire la clé de 256 bits.

J’ai réécrit les fonctions `DecryptMessage` et `DeriveKey` en Python, puis j’ai tenté de déchiffrer le dernier message — dont nous connaissions le contenu déchiffré — en utilisant l’identifiant intercepté via BurpSuite : : 

```python
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Fonction pour déchiffrer le message
def decrypt_message(encrypted_message, device_id):
    try:
        key = derive_key(device_id, "s3cr3t_s@lt")
        iv = base64.b64decode("LJo+0sanl6E3cvCHCRwyIg==")
        encrypted_data = base64.b64decode(encrypted_message)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception:
        return None
    
# Fonction pour dériver la clé
def derive_key(device_id, salt):
    device_id_with_salt = f"{device_id}:{salt}"
    derived_key = hashlib.sha256(device_id_with_salt.encode('utf-8')).digest()
    return derived_key

encrypted_message = "XeRtXUezp7oP9fqmL1mCho48gIf1weTI6CK09Nl7ZtmonWC9yOFTqbqlSeTgFRXVrYPTPYLtynBIieLafbViGo2JXQ6/E2rPPpS+7afHr/S28VtsIncUNx66q6qPvFT9"
device_id = "5vmObbpVKWesTEbiSxlCzXSEXFUwues1nVIGiMYOED8="

print(decrypt_message(encrypted_message, device_id))
```

Le résultat est concluant :
```bash
$ python3 decrypt.py
URGENT: DGSE is on our trail. They got one of us. Destroy all traces and go dark
```

## 🔑 Déchiffrement des autres messages

Maintenant que nous maîtrisons la logique de déchiffrement, il nous faut retrouver l'identifiant (**device_id**) utilisé sur l'ancien appareil. D’après le brief de mission, celui-ci est généré à partir du MODEL et du BRAND de l'appareil.

Voici la fonction Python qui permet de reproduire cette génération :
```python
def hash_device_id(model, brand):
    device_id = f"{model}:{brand}"
    hashed_device_id = hashlib.sha256(device_id.encode('utf-8')).digest()
    return base64.encodebytes(hashed_device_id).decode('utf-8').strip()
```
DOn sait également que l'appareil saisi appartient à la marque Google. On peut donc itérer sur tous les modèles d'appareils Google connus, générer leur device_id, et tenter de déchiffrer les messages un par un. La liste officielle des [appareils compatibles avec Google Play][devices] nous servira de base.

[devices]: https://storage.googleapis.com/play_public/supported_devices.html

Voici le script final : 

```python
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import csv

# Fonction pour hasher l'identifiant du device
def hash_device_id(model, brand):
    device_id = f"{model}:{brand}"
    hashed_device_id = hashlib.sha256(device_id.encode('utf-8')).digest()
    return base64.encodebytes(hashed_device_id).decode('utf-8').strip()

# Fonction pour dériver la clé
def derive_key(device_id, salt):
    device_id_with_salt = f"{device_id}:{salt}"
    derived_key = hashlib.sha256(device_id_with_salt.encode('utf-8')).digest()
    return derived_key

# Fonction pour déchiffrer le message
def decrypt_message(encrypted_message, model, brand):
    try:
        device_id = hash_device_id(model, brand)
        key = derive_key(device_id, "s3cr3t_s@lt")
        iv = base64.b64decode("LJo+0sanl6E3cvCHCRwyIg==")
        encrypted_data = base64.b64decode(encrypted_message)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception:
        return None

# Chargement des configs depuis un fichier CSV
device_configs = []
with open("devices.csv", newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # ignorer l'en-tête
    for brand, model in reader:
        if brand == "Google":
            device_configs.append((model, brand))

# Message chiffré
encrypted_message = "Swz/ycaTlv3JM9iKJHaY+f1SRyKvfQ5miG6I0/tUb8bvbOO+wyU5hi+bGsmcJD3141FrmrDcBQhtWpYimospymABi3bzvPPi01rPI8pNBq8="

# Bruteforce
for model, brand in device_configs:
    print(f"Testing with model: {model}, brand: {brand}")
    decrypted_message = decrypt_message(encrypted_message, model, brand)
    if decrypted_message:
        print(f"✅ Decrypted message: {decrypted_message}")
        break
    else:
        print("❌ Failed to decrypt\n")
```

```bash
$ python3 decrypt.py
Testing with model: guybrush, brand: Google
❌ Failed to decrypt

Testing with model: skyrim, brand: Google
❌ Failed to decrypt

Testing with model: zork, brand: Google
❌ Failed to decrypt

...

Testing with model: Yellowstone, brand: Google
✅ Decrypted message: Keep this safe. RM{788e6f3e63e945c2a0f506da448e0244ac94f7c4}
```
Nous apprenons ainsi que l’appareil utilisé était un Google Yellowstone. Et nous récupérons le flag :
`RM{788e6f3e63e945c2a0f506da448e0244ac94f7c4}`

Voici tous les autres messages déchiffrés avec ce même identifiant : 
```plaintext
✅ Decrypted message: Target acquired. Hospital network vulnerable. Initiating ransomware deployment.
✅ Decrypted message: New target identified. School district network. Estimated payout: 500k in crypto.
✅ Decrypted message: New ransomware strain ready for deployment. Testing phase complete.
✅ Decrypted message: Security patch released. Need to modify attack vector. Meeting at usual place.
✅ Decrypted message: New zero-day exploit in a linux binary discovered. Perfect for next operation. Details incoming.
✅ Decrypted message: Payment received. Sending decryption keys now. Next target: City infrastructure.
✅ Decrypted message: Encryption complete. Ransom note deployed. 48h countdown started.
✅ Decrypted message: URGENT: DGSE is on our trail. They got one of us. Destroy all traces and go dark.
```


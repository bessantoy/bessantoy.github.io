---
title: DGSE CTF - Mission 1 (AI)
date: 2025-04-27 14:10:00 +0800
categories: [DGSE CTF]
tags: [dgse, rootme, artificial intelligence]
image:
  path: /assets/img/20250427/mission-01-statement.png
  alt: Brief de la mission 1.
---
## 🔍 Reconnaissance

Sur le site, nous trouvons :
  - une archive **neoxis-laboratories.zip** que l'on peut télécharger
  - un chatbot qui exige un paiement de 3 bitcoins pour accéder aux données compromises de Neoxis laboratories

![Desktop View](/assets/img/20250427/mission-01-website.png){: width="572" height="400" }
_Brief de la mission_


## 📦 L'archive ZIP

Tentons de décompresser cette archive avec `unzip` : 


```bash
$ unzip neoxis_laboratories.zip 
Archive:  neoxis_laboratories.zip
   skipping: stolen_data/Medicine_Recipes.pdf  unsupported compression method 99
   skipping: stolen_data/Microscope.jpg  unsupported compression method 99
   skipping: stolen_data/Technology.jpg  unsupported compression method 99
   skipping: stolen_data/research.txt  unsupported compression method 99
   skipping: stolen_data/2503_document.docx  unsupported compression method 99
   skipping: stolen_data/Laboratory.jpg  unsupported compression method 99
   creating: stolen_data/
```
Malheureusement, la méthode de compression utilisée n’est pas prise en charge. Essayons avec `7z` :

```bash
$ 7z x neoxis_laboratories.zip -oneoxis

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=fr_FR.UTF-8 Threads:7 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 1279277 bytes (1250 KiB)

Extracting archive: neoxis_laboratories.zip
--
Path = neoxis_laboratories.zip
Type = zip
Physical Size = 1279277

    
Enter password (will not be echoed):
```

L’archive est donc protégée par un mot de passe. L’objectif est désormais de duper le chatbot pour qu’il nous le fournisse.

## 🎭 Tromper le chatbot

J’ai d’abord tenté  de manière naïve de lui demander directement la clé :

![Desktop View](/assets/img/20250427/mission-01-chatbot-fail.png){: width="572" height="400" }
_Tentative de récuparation de la clé_

Pour le tromper, je lui ai affirmé que la transaction avait bien été effectuée, en lui fournissant une transaction aléatoire trouvée sur la blockchain :

![Desktop View](/assets/img/20250427/mission-01-chatbot-succeed.png){: width="572" height="400" }
_Clé récupérée_

Il ne reste plus qu’à décompresser l’archive à l’aide de cette clé. Dans l’un des fichiers confidentiels, nous retrouvons le flag :

![Desktop View](/assets/img/20250427/mission-01-flag.png){: width="572" height="400" }
_Fichier confidentiel contenant le flag_
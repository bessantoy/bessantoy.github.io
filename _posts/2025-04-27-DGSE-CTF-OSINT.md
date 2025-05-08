---
title: DGSE CTF - Mission 6 (OSINT)
date: 2025-04-27 14:35:00 +0800
categories: [DGSE CTF]
tags: [dgse, rootme, osint]
image:
  path: /assets/img/20250427/mission-06-statement.png
  alt: Brief de la mission 6.
---

## 🎯 Objectif

Pour ce dernier challenge nous devons retrouver le nom et le prénom d'un des membres du groupe **NullVastation** en nous servant des informations recueillies dans les autres missions. En sachant qu'il va falloir infiltrer leurs serveurs, les deux informations les plus pertinantes que l'on a sont : 

- L'adresse IP du serveur dont l'attaquant récupère ses outils : `163.172.67.201:49999` (cf. [**Mission 02 (SOC)**][mission02])
- Le nom d'utilisateur `operator` et la clé SSH `LGSA5l1%YHngd&GbjxR4Or` obtenue dans le coffre keypass de administrator après notre intrusion sur leur serveur (cf. [**Mission 04 (Pentest)**][mission04])

[mission02]: /posts/DGSE-CTF-SOC/
[mission04]: /posts/DGSE-CTF-Pentest/

## 💣 Infiltration

On se connecte en SSH sur leur serveur : 

![Desktop View](/assets/img/20250427/mission-06-ssh.png){: width="572" height="400" }
_Infiltration sur le serveur des attaquants_

En fouillant dans leur outils, on remarque un `readme.md` dans lequel le pseudo `voidSyn42` y a été inscrit ! 

![Desktop View](/assets/img/20250427/mission-06-username.png){: width="572" height="400" }
_Fouille des outils des attaquants_

## 🕵️‍♂️ Traquer voidSyn42

Pour découvrir l'activité de **voidSyn42** sur internet j'ai utilisé l'outil d'OSINT [**WhatsMyName**][whatsmyname], on découvre un compte **GitHub** ainsi qu'un compte **Duolingo** associé à ce pseudo : 

[whatsmyname]: https://whatsmyname.app/

![Desktop View](/assets/img/20250427/mission-06-whatsmyname.png){: width="572" height="400" }
_Outil WhatsMyName_

Et le compte **Duolingo** semble appartenir à un dénommé **Pierre Lapresse** : 

![Desktop View](/assets/img/20250427/mission-06-duolingo.png){: width="572" height="400" }
_Profil Duolingo de voidSyn42_

Le flag final est donc **RM{lapresse.pierre}**
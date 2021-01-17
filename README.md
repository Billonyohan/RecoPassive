# RecoPassive
 
<p align="center">
  <img src=https://github.com/Billonyohan/RecoPassive/blob/main/logo.png />
</p>
RecoPassive is very simple to use, effective tool builded to be used by pentester or red team for passive recognition.
The tool gathers many data like emails, names, subdomains, IPs, URLs, registrar ... from other tools like :


  - Whois

  - Dig
  
  - Host
  
  - TheHarvester
  
  - Nslookup
  
  - Dnsenum


### Installation

RecoPassive requires [Python 3.8](https://www.python.org/downloads/release/python-380/).

Install the dependencies 

```sh
$ git clone https://github.com/Billonyohan/RecoPassive
$ (optional) python3 -m  venv env 
$ (optional) source env/bin/activate
$ pip3 install -r requirements.txt
```

Run 

```sh
$ python3 recoPassive.py
```

### Todos

 - Output a file in XML
 - Write some Tests
 - Create ElectronJS application (GUI)

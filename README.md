# LICMA(Language Independent Crypto-Misuse Analysis)

LICMA is a an analysis tool to identify incorrect initialization of crypto functions.
The performed analysis is based on the six rule by Egele et al. [1]

It is possible to create own rules for individual analyses.

## Requirements
- [docker](https://docs.docker.com/get-docker/)
- [docker-compose](https://docs.docker.com/compose/install/)

We included all further requirements such as babelfish into the docker container. 

## Installation
1. Clone this repository (git clone https://github.com/stg-tud/licma.git).
2. Set the environment variable DATA in the file [.env](.env). This variable
defines the directory were the data is located that should by analysed.
By starting the docker container this diretory is linked to /usr/data of
the docker container licma.
3. Start a terminal and change to the directory were the file [docker-compose.yml](docker-compose.yml)
is located.
4. Start the docker containers by entering: `$ docker-compose up`

Now the docker containers licma and bblfsh are started. You can see them witch `$ docker ps -a`. 

## Execute the licma.py script
1. Verify that the docker containers licma and bblfsh are running.
2. Start a terminal and change to the directory were the file [docker-compose.yml](docker-compose.yml)
is located.
3. Execute the licma.py script with the following command:
`$ docker-compose exec licma python3 run_licma.py -i /usr/data/path of file or directory that should be analysed --lc`


##### LICMA options:
- [--lo] output log file (defalut: '../log')
- [--ll] log level: CRITICAL = 50 ERROR = 40 WARNING = 30 INFO = 20 DEBUG = 10 NOTSET = 0 (default=10)
- [--lc] print logging on cli
- [--la] source file type ('java' or 'py' default='java')
- [--lib] select cryptographic library ONLY FOR PYTHON ('pycrypto' or 'm2crypto' or 'pynacl' or 'ucryptolib' or 'cryptography' or '*', default='*')
- [--num] select a specific rule (type=int, default=None: that means, all rules are considered for the analysis)
- [-i] input directory or file
- [-o] output directory (default='../output')

## Publications

LICMA was used in the publication **Python Crypto Misuses in the Wild**. 
This are the evaluation and scripts for out paper: **Python Crypto Misuses in the Wild** by
<a itemprop="sameAs" content="https://orcid.org/0000-0002-1441-2423" href="https://orcid.org/0000-0002-1441-2423" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Anna-Katharina Wickert<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>, <a itemprop="sameAs" content="https://orcid.org/0000-0002-5805-2773" href="https://orcid.org/0000-0002-5805-2773" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Lars Baumgärtner<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>, <a itemprop="sameAs" content="https://orcid.org/0000-0003-2337-1819" href="https://orcid.org/0000-0003-2337-1819" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Florian Breitfelder<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>, and <a itemprop="sameAs" content="https://orcid.org/0000-0001-6563-7537" href="https://orcid.org/0000-0001-6563-7537" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Mira Mezini<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>.
Technische Universität Darmstadt, D-64289 Darmstadt, Germany.

## References
[1] Manuel Egele, David Brumley, Yanick Fratantonio, and Christopher Kruegel.
An empirical study of cryptographic misuse in android applications. In Ahmad-Reza Sadeghi, Virgil Gligor, and Moti Yung, editors,
Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security - CCS '13, pages 73-84, New York, New York, USA, 2013. ACM Press.

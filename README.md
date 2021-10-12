# LICMA(Language Independent Crypto-Misuse Analysis)

LICMA is a multi-language analysis tool to identify incorrect initialization of crypto functions.
The current rule set is based on the six rules defined by Egele et al. [^1]. We provide an overview of the rules and Python examples [below](https://github.com/stg-tud/licma#crypto-rules).

It is possible to create own rules for individual analyses or support additional languages.

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
- [-i] input directory or file]
- [-o] output directory (default='../output')


## Crypto Rules

| **ID** | **Rule**                                                                                           | **Python: Violation Example**                                                                                         |
|--------|----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| §1     | Do not use electronic code book (ECB) mode for encryption.                                         | `aes = AES.new(key, AES.MODE_ECB)`                                                                      |
| §2     | Do not use a non-random initiliazation vector (IV) for ciphertext block chaining (CBC) encryption. | `aes = AES.new(key, AES.MODE_CBC, b'\0' * 16)`                                                             |
| §3     | Do not use constant encryption keys.                                                               | `aes = AES.new(b'\0' * 32, AES.MODE_CBC, iv)`                                                               |
| §4     | Do not use constant salts for password-based encryption (PBE).                                     | `kdf = PBKDF2HMAC(hashes.SHA256(), 32, b'\0' * 32, 10000)`                                                  |
| §5     | Do not use fewer than 1,000 iterations for PBE.                                                    | `kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 1)`                                                            |
| §6     | Do not use static seeds to initialize secure random generator.                                     | Due to API design only possible in  Java [^1] and C/C++ [^2] |

## Evaluation

We evaluated the Java component of LICMA upon the benchmark *CryptoAPIBench* and the Python component in a in-the-wild study. You can find more details in our [results GitHub project](https://github.com/stg-tud/python-crypto-misuses-study-results) or respectively on [figshare](https://doi.org/10.6084/m9.figshare.16499085.v1). 


## Publication

LICMA was used in the publication **Python Crypto Misuses in the Wild**. 
This are the evaluation and scripts for out paper: **Python Crypto Misuses in the Wild** by
<a itemprop="sameAs" content="https://orcid.org/0000-0002-1441-2423" href="https://orcid.org/0000-0002-1441-2423" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Anna-Katharina Wickert<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>, <a itemprop="sameAs" content="https://orcid.org/0000-0002-5805-2773" href="https://orcid.org/0000-0002-5805-2773" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Lars Baumgärtner<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>, <a itemprop="sameAs" content="https://orcid.org/0000-0003-2337-1819" href="https://orcid.org/0000-0003-2337-1819" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Florian Breitfelder<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>, and <a itemprop="sameAs" content="https://orcid.org/0000-0001-6563-7537" href="https://orcid.org/0000-0001-6563-7537" target="orcid.widget" rel="me noopener noreferrer" style="vertical-align:left;">Mira Mezini<img src="https://orcid.org/sites/default/files/images/orcid_16x16.png" style="width:1em;margin-left:.5em;" alt="ORCID iD icon"></a>.
Technische Universität Darmstadt, D-64289 Darmstadt, Germany.

## References
[^1]: Manuel Egele, David Brumley, Yanick Fratantonio, and Christopher Kruegel. An empirical study of cryptographic misuse in android applications. In Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security - CCS '13, New York, USA, 2013. ACM Press.
[^2]: Zhang, Li, Jiongyi Chen, Wenrui Diao, Shanqing Guo, Jian Weng, and Kehuan Zhang. ‘CryptoREX: Large-Scale Analysis of Cryptographic Misuse in IoT Devices’. In 22nd International Symposium on Research in Attacks, Intrusions and Defenses (RAID 2019), Chaoyang District, Beijing: USENIX Association, 2019. 


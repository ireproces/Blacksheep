# Vuln2ATT&CK project

Vuln2ATT&CK is designed to analyze the most common vulnerabilities affecting standard services active on network hosts.
Its goal is to map each vulnerability (CVE) to the techniques or tactics from the ATT&CK matrix used to exploit it. This allows even basic users to understand the security status of their system or network while providing direct references to the best mitigation strategies.

The project includes a lab developed using the [Kathara tool](https://github.com/KatharaFramework/Kathara), the lab hosts an active Caldera server and several other hosts for testing purposes.
It utilizes the [MITRE Caldera framework](https://github.com/mitre/caldera), combined with the [Pathfinder plugin](https://github.com/center-for-threat-informed-defense/caldera_pathfinder), to perform scans and collect and data.

The [CVE-ListV5](https://github.com/CVEProject/cvelistV5) repository and [CAPECList](https://capec.mitre.org/index.html) are used as databases for the mappings. Finally, the [MITRE Python library](https://github.com/mitre-attack/mitreattack-python) is used for communication with the ATT&CK matrix.

## Network topology and service table

![](rete.jpeg)

| Host    | Service   | Version    | Ports                  | Source                                                                      |
|---------|-----------|------------|------------------------|-----------------------------------------------------------------------------|
| pc1     | Tomcat    | 9.0.30     | 8080,8009              | [Ref](https://github.com/vulhub/vulhub/tree/master/tomcat/CVE-2020-1938)    |
| pc2     | libssh    | 0.8.1      | 2222,22                | [Ref](https://github.com/vulhub/vulhub/tree/master/libssh/CVE-2018-10933)   |
| pc3     | OpenSSL   | 7.6        | 22                     | [Ref](https://vulners.com/cve/CVE-2018-15473)                               |
| pc4     | OFBiz     | 18.12.15   | 8443,5005              | [Ref](https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2024-45195)    |
| pc5     | SaltStack | 3.0.2      | 8000,2222,22,4505,4506 | [Ref](https://github.com/vulhub/vulhub/tree/master/saltstack/CVE-2020-16846)|
| pc6     | OFBiz     | 17.12.01   | 8443,5005              | [Ref](https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2020-9496)     |
| pc7     | OFBiz     | 18.12.09   | 8443,5005              | [Ref](https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2023-49070)    |

## Requirements
* Any Linux or MacOS
* Python 3.12+ (with Pip3)
* [Katharà](https://github.com/KatharaFramework/Kathara/wiki/Installation-Guides)

## Installation
All `git clone` MUST be executed in the same directory!
* Clone this repository:
    ```Bash
    git clone https://github.com/ireproces/Vuln2ATT-CK.git
    ```
* Clone the cvelistV5 repository:
    ```Bash
    git clone https://github.com/CVEProject/cvelistV5.git
    ```
* Clone the mitreattack-python repository:
    ```Bash
    git clone https://github.com/mitre-attack/mitreattack-python.git
    cd mitreattack-python
    pip install -r requirements-dev.txt
    pip install mitreattack-python
    ```

# User Guide
This guide provides an example of analyzing an entire network. Each scan gathers information about the vulnerabilities (CVEs) of a portion of the network, the mapping program consolidates the CVEs and maps them to the ATT&CK matrix.
Scans can also be performed on individual hosts, provided there is only one .xml.yml scan file for the host in the /mapping directory

## Phase 1: Lab Setup 
1. Start all testing hosts by navigating to the /lab directory and executing these commands from within:
    ```Bash
    kathara lstart
    kathara lconfig --name server --add A
    ```
    - wait for all hosts to start correctly before executing the second command

2. Set the CALDERA server host configuration by executing these commands from the server host terminal:
    ```Bash
    bash configure_iface.sh
    ```

## Phase 2: Scans Setup
1. Open a browser and access `http://localhost:8888`. Log in as the red user using the username and password specified in the file `/lab/server/caldera/conf/local.yml`

2. From the Caldera homepage select the Pathfinder plugin and fill the Scan view fields as follows:  
    - Select a scanner: nmap  
    - Target specification: IP address or subnet to scan (e.g. 11.1.0.0/24 or 11.1.0.2)  
    - Scanner script: [nmap-vulners](https://github.com/vulnersCom/nmap-vulners/tree/bbf53dd085f8d810921ee00ccf85bdb329d59514)
    - Ports: insert some common ports (refer to the service table for more details)
    - No ping: check this box
    - Report name: provide a unique name
    
    press the button to start the scan and check the output to track its status

3. After the scan completes, go to the Reports view to generate a graph of the detected vulnerabilities and download the report

4. Move the downloaded reports to the /mapping folder within the Vuln2ATT&CK project. You should already see the `mapper.py` program inside this folder

## Phase 3: Mapping
1. From the /mapping folder, execute the program with the following command:
    ```Bash
    python3 mapper.py
    ```

The results will be printed in the terminal, and an output.txt file will be created (or overwritten if it already exists) to facilitate viewing.
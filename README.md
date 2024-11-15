# Blacksheep project

Blacksheep was designed to analyze the most common vulnerabilities affecting standard services active on network hosts.

It utilizes the [MITRE Caldera framework](https://github.com/mitre/caldera), combined with the [Pathfinder plugin](https://github.com/center-for-threat-informed-defense/caldera_pathfinder), to collect and process the acquired information.

The project includes a laboratory developed using the [Kathara tool](https://github.com/KatharaFramework/Kathara), within which the Caldera server and a series of other network hosts are active for testing purposes.

## Network topology and <host,service> table

![](rete.jpeg)

| Host    | Service   | Version    | Ports      | Source                                                                    |
|---------|-----------|------------|------------|---------------------------------------------------------------------------|
| pc1     | Tomcat    | 9.0.30     | 8080,8009  | [Ref](https://github.com/vulhub/vulhub/tree/master/tomcat/CVE-2020-1938)  |
| pc2     | libssh    | 0.8.1      | 2222,22    | [Ref](https://github.com/vulhub/vulhub/tree/master/libssh/CVE-2018-10933) |
| pc3     | openssl   | 7.6        | 22         | [Ref](https://vulners.com/cve/CVE-2018-15473)                             |
| pc4     |  ...      |     ...    |    ...     |                    ...                                                    |
| pc5     |  ...      |     ...    |    ...     |                    ...                                                    |
| pc6     |  ...      |     ...    |    ...     |                    ...                                                    |

## Installation guide

1. clone this repository into your local directory

2. navigate to the directory /Blacksheep/lab and execute this command from within
    ```Bash
    kathara lstart
    ```

3. when all the hosts are up, from the server terminal, execute this command
    ```Bash
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    ```

4. access the address `http://localhost:8888` from your default browser and login as red user - username and password are specified in the file `/lab/server/caldera/conf/local.yml`

5. select the Pathfinder plugin and fill in the fields as follows:  
    - Select a scanner: nmap  
    - Target specification: IP address or subnet to scan (e.g. 11.1.0.0/24)  
    - Scanner script: [nmap-vulners](https://github.com/vulnersCom/nmap-vulners/tree/bbf53dd085f8d810921ee00ccf85bdb329d59514)
    - Ports: specify some common ports (refer to the service table for more details)
    - No ping: selected
    - Report name: unique

6. work in progess...
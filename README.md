# Blacksheep project

Blacksheep was designed to analyze the most common vulnerabilities affecting standard services active on network hosts.

It utilizes the [MITRE Caldera framework](https://github.com/mitre/caldera), combined with the [Pathfinder plugin](https://github.com/center-for-threat-informed-defense/caldera_pathfinder), to collect and process the acquired data.

The project includes a lab developed using the [Kathara tool](https://github.com/KatharaFramework/Kathara), within which the Caldera server and a series of other hosts are active for testing purposes.

## Network topology and service table

![](rete.jpeg)

| Host    | Service   | Version    | Ports                  | Source                                                                      |
|---------|-----------|------------|------------------------|-----------------------------------------------------------------------------|
| pc1     | Tomcat    | 9.0.30     | 8080,8009              | [Ref](https://github.com/vulhub/vulhub/tree/master/tomcat/CVE-2020-1938)    |
| pc2     | libssh    | 0.8.1      | 2222,22                | [Ref](https://github.com/vulhub/vulhub/tree/master/libssh/CVE-2018-10933)   |
| pc3     | openssl   | 7.6        | 22                     | [Ref](https://vulners.com/cve/CVE-2018-15473)                               |
| pc4     | ofbiz     | 18.12.15   | 8443,5005              | [Ref](https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2024-45195)    |
| pc5     | saltstack | 3.0.2      | 8000,2222,22,4505,4506 | [Ref](https://github.com/vulhub/vulhub/tree/master/saltstack/CVE-2020-16846)|
| pc6     | ofbiz     | 17.12.01   | 8443,5005              | [Ref](https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2020-9496)     |
| pc7     | ofbiz     | 18.12.09   | 8443,5005              | [Ref](https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2023-49070)    |

## Operational requirements

    * Any Linux or MacOS
    * Python 3.12+ (with Pip3)
    * [Katharà framework](https://github.com/KatharaFramework/Kathara/wiki/Installation-Guides)

## Installation

Clone this repository into your local directory

## Usage

1. Navigate to the directory /lab and execute this command from within
    ```Bash
    kathara lstart server
    ```

2. When the host is up, execute this command from its terminal
    ```Bash
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    ```
    to verify that the operation was successful, execute a ping to google.com

3. Access the address `http://localhost:8888` from your default browser and login as red user - username and password are specified in the file `/lab/server/caldera/conf/local.yml`

4. After verifying that the Caldera homepage is accessible, run this command to start the remaining hosts
    ```Bash
    kathara lstart pc1 pc5 pc7 r1 fw r2 r3 pc2 pc4 pc3 pc6 web1
    ```

5. From the Caldera homepage select the Pathfinder plugin and fill the Scan view fields as follows:  
    - Select a scanner: nmap  
    - Target specification: IP address or subnet to scan (e.g. 11.1.0.0/24)  
    - Scanner script: [nmap-vulners](https://github.com/vulnersCom/nmap-vulners/tree/bbf53dd085f8d810921ee00ccf85bdb329d59514)
    - Ports: insert some common ports (refer to the service table for more details)
    - No ping: selected
    - Report name: unique
    
    Press the button to start the scan and check the output to track its status

6. Once the scan is complete, go to the Reports view to generate the graph of detected vulnerabilities and download the generated report

7. Move the reports from the download folder (or the folder you have set as default for downloaded files) to the reports folder within the Blacksheep project - you should already see the `join_reports.py` program inside

8. From the /reports folder, run the command to execute the program
    ```Bash
    python3 join_reports.py
    ```
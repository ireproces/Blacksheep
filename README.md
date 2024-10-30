A simple reference network containing a Caldera server within the Pathfinder plugin enabled and other test hosts

Guide:
1. clone the repository into a local directory
2. navigate to the directory /lab and execute the command `kathara lstart` from within
3. when all the hosts are up, access the address `localhost:8888` from your browser
4. use the Pathfinder plugin to scan domains or hosts,
   or execute the command `nmap -sV --script vulners IP_ADDR -v --dns-servers 8.8.8.8` from the terminal of the server (lab host)
5. work in progess...
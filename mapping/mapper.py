import os
import yaml
import json
import xml.etree.ElementTree as ET
import re
from mitreattack.stix20 import MitreAttackData
from datetime import datetime

# Ritorna un set di cve id estratti dal file in input
def extract_cves(file_path):
    output = set() # set di cve id

    # apertura del file
    try:
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)

        # scorre sui valori dei dizionari host
        for host in data.get("hosts", {}).values():
            # estrae ed aggiunge lista di cve
            output.update(host.get("cves", []))

    # gestione delle eccezioni
    except yaml.YAMLError as e:
        print(f"  ERROR: Could not parse YAML file {file_path}: {e}")
    except Exception as e:
        print(f"  ERROR: Unexpected error while extracting CVE-IDs from {file_path}: {e}")

    return output

# Ritorna un set di cve id da tutti i file .xml.yml contenuti nella directory in input
def get_all_cves_from_all_scans(directory):
    output = set() # set di cve id

    # accesso alla directory
    try:

        # scorre tutti i file contenuti nella directory in input
        for file_name in os.listdir(directory):

            # seleziona solo i file con estensione finale .xml.yml = file report di pathfinder
            if file_name.endswith(".xml.yml"):
                file_path = os.path.join(directory, file_name) # costruisce il percorso completo del file
                
                # funzione per l'estrazione delle cve
                cves_single_report = extract_cves(file_path)

                output.update(cves_single_report) # aggiunta all'output, rimuove duplicati

    # gestione delle eccezioni
    except FileNotFoundError as e:
        print(f"  ERROR: Directory {directory} not found: {e}")
    except PermissionError as e:
        print(f"  ERROR: Permission denied to access {directory}: {e}")
    except Exception as e:
        print(f"  ERROR: Unexpected error while processing reports in {directory}: {e}")

    return output

# ritorna il file path completo per il file CVE-YYYY-NXXX.json relativo alle cve in input
def get_cve_id_file_path_json(cve, cves_directory):
    
    #divide la stringa ai caratteri "-" --> CVE/YYYY/NXXX
    parts = cve.split("-")
    if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit(): # verifica di correttezza
        exit

    year = parts[1] # YYYY
    number = parts[2] # NXXX

    # estrazione N per la ricerca nella directory
    if len(number) > 3:
        exit
    n_key = f"{number[:-3]}xxx"

    # costruisce path completo
    cve_path = os.path.join(cves_directory, year, n_key, f"{cve}.json")
    if not os.path.exists(cve_path): # verifica di correttezza
        exit

    return cve_path

# funzione che ritorna il set di cwe id contenuti nel file in input
def get_cwes_for_cve(cve_id, cve_file_path):
    
    try:
        # apertura del file
        with open(cve_file_path, "r") as json_file:
            cve_data = json.load(json_file)

        output = set()

        cna_container = cve_data.get("containers", {}).get("cna", {}) # dizionario cna
        problem_types = cna_container.get("problemTypes", []) # dizionario di dizionari problemTypes
            
        for dict in problem_types: # itera dizionari contenuti
            descriptions = dict.get("descriptions", []) # dizionario descriptions
                
            for field in descriptions: # itera sui campi del dizionario
                cwe_id = field.get("cweId") # campo cweId
                if cwe_id:
                    output.add(cwe_id)


    # gestione delle eccezioni
    except json.JSONDecodeError as e:
        print(f"  ERROR: Could not parse JSON for {cve_id} at {cve_file_path}: {e}")
    except Exception as e:
        print(f"  ERROR: Unexpected error for {cve_id} at {cve_file_path}: {e}")

    return output

# funzione che ritorna la lista di capec id che contengono il cwe id in input
def get_all_capecs_for_cwe(cwe_set, capecs_file_path):
    ns = {"capec": "http://capec.mitre.org/capec-3"}
    output=set()

    try:
         # caricamento del file .xml
        tree = ET.parse(capecs_file_path)
        root = tree.getroot()

        for attack_pattern in root.findall(".//capec:Attack_Patterns/capec:Attack_Pattern", ns): # itera sul dizionario <Attack_Patterns>
        
            related_weaknesses = attack_pattern.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", ns) # dizionario <Related_Weaknesses>
            for weakness in related_weaknesses: # itera sugli elementi <Related_Weakness>
            
                for cwe_id in cwe_set:
                    cwe_id_no_prefix = cwe_id.split("-")[1] # isola id numerico CWE- nnn 
                    if weakness.attrib.get("CWE_ID") == cwe_id_no_prefix:
                        output.add(attack_pattern.attrib.get("ID"))

    except ET.ParseError as e:
        print(f"ERROR: Could not parse CAPECs XML file: {e}")
    except FileNotFoundError as e:
        print(f"ERROR: CAPECs file not found: {e}")
    except Exception as e:
        print(f"ERROR: Unexpected error while processing CAPECs mapping: {e}")
    
    return output

# funzione che ritorna un dizionario che associa ogni cve id del set in ingresso con
# i capec ids contenuto nel file in input, attraverso l'uso dei cwe id
def get_all_capecs_for_all_cves(all_cves, cves_directory, capecs_matrix_file_path):

    output = {} # dizionario finale

    for cve_id in all_cves: # itera i cve id in input
        cve_file_path = get_cve_id_file_path_json(cve_id, cves_directory) # construisce file path per il json del cve record
        
        cwe_set = get_cwes_for_cve(cve_id, cve_file_path) # estrae cwe id associati alla cve
        capec_set=get_all_capecs_for_cwe(cwe_set, capecs_matrix_file_path)

        if cwe_set and capec_set:
            output[cve_id]=capec_set
    
    return output


# funzione che ritorna un dizionario <cve id, [tech ids]>
def get_all_techs_for_all_cves(cve2capecs, capecs_file_path):
    output = {}
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    try:
        # caricamento del file .xml
        tree = ET.parse(capecs_file_path)
        root = tree.getroot()

        for cve_id, capec_ids in cve2capecs.items():
            tech_set=set()
            for capec_id in capec_ids:
                
                attack_pattern = root.find(f".//capec:Attack_Pattern[@ID='{capec_id}']", ns)
                if attack_pattern is not None:
                    for taxonomy_mapping in attack_pattern.findall(".//capec:Taxonomy_Mapping[@Taxonomy_Name='ATTACK']", ns):
                        for entry in taxonomy_mapping.findall(".//capec:Entry_ID", ns):
                            tech_id = entry.text.strip()
                            formatted_tech_id = f"T{tech_id}"
                            tech_set.add(formatted_tech_id)

            if tech_set:
                output[cve_id] = tech_set

    except ET.ParseError as e:
        print(f"ERROR: Could not parse CAPECs XML file: {e}")
    except FileNotFoundError as e:
        print(f"ERROR: CAPECs file not found: {e}")
    except Exception as e:
        print(f"ERROR: Unexpected error while processing CAPECs mapping: {e}")

    return output

# funzione che ritorna il set di capec ids contenuti nel campo Nature="CanPrecede" del capec record recuperato dal file in input
def get_related_capecs_for_capec(capec_id, capecs_file_path):
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    try:
        # caricamento del file .xml
        tree = ET.parse(capecs_file_path)
        root = tree.getroot()
        
        output=set()

        attack_pattern = root.find(f".//capec:Attack_Pattern[@ID='{capec_id}']", ns)
        if attack_pattern is not None:
            related_patterns = attack_pattern.findall(".//capec:Related_Attack_Patterns/capec:Related_Attack_Pattern", ns) # dizionario <Related_Attack_Patterns>
            for pattern in related_patterns: # itera sugli elementi <Related_Attack_Pattern>
                if pattern.attrib.get("Nature") == "CanPrecede":
                    output.add(pattern.attrib.get("CAPEC_ID"))

    except ET.ParseError as e:
        print(f"ERROR: Could not parse CAPECs XML file: {e}")
    except FileNotFoundError as e:
        print(f"ERROR: CAPECs file not found: {e}")
    except Exception as e:
        print(f"ERROR: Unexpected error while processing CAPECs mapping: {e}")

    return output

# Program entry point
if __name__ == "__main__":

    scans_directory = "." # contiene report
    cves_directory = "./../../cvelistV5/cves" # repository cve list
    capecs_file_path = "./658.xml" # matrice capec mappata su ATT&CK

    matrix_file_path = "./enterprise-attack.json" # matrice ATT&CK
    mitre_attack_data = MitreAttackData(matrix_file_path)

    output_file = "./output.txt" # file per l'output finale del programma

    # Fase 1: estrazione CVE ID totali della rete
    all_cves = get_all_cves_from_all_scans(scans_directory)

    # Fase 2: creazione del dizionario CVE ID: [CAPEC IDs]
    cve2capecs = get_all_capecs_for_all_cves(all_cves, cves_directory, capecs_file_path)

    ### AGGIUNTA ENTRY cve2capecs PER VERIFICA FUNZIONE links
    cve2capecs[list(cve2capecs.keys())[0]].add('14')

    # Fase 2: creazione del dizionario CVE ID: [Technique IDs]
    cve2techs = get_all_techs_for_all_cves(cve2capecs, capecs_file_path)

    # Fase 3: produzione dell'output
    try:
        # apertura del file, appende al contenuto
        with open(output_file, "a") as file:
            file.write(f"MAPPING PERFORMED AT DAY: {datetime.now().strftime("%Y-%m-%d")} AT {datetime.now().strftime("%H:%M:%S")}\n")
            file.write("----------------------------------------------------------------------------------\n")
        
            for cve_id in all_cves: # itera tutte le CVE rilevate
                file.write(f"Vuln-ID: {cve_id}")

                if cve_id in cve2techs: # verifica che siano mappate su ATT&CK
                    file.write(" - mapping available:\n")
                    file.write("* can be exploited through:\n")

                    techs_set=cve2techs[cve_id] # lista di tecniche ricollegabili alla CVE
                    for tech_id in techs_set: # itera tecniche

                        tech = mitre_attack_data.get_object_by_attack_id(tech_id, "attack-pattern") # struttura della tenica dalla matrice
                        external_id = None
                        for ref in tech.get('external_references', []):
                            if ref.get('source_name') == 'mitre-attack':
                                external_id = ref.get('external_id')
                                break
                        file.write(f"   External ID: {external_id}, Name: {tech['name']}\n")

                    file.write("* can facilitate the exploitation of:\n")
                    capecs_set=cve2capecs[cve_id] # lista di capec ids ricollegabili alla CVE
                    for capec_id in capecs_set: # itera capec ids
                        
                        # funzione che ritorna il set di capec id child linked
                        related_capecs=get_related_capecs_for_capec(capec_id, capecs_file_path)
                        for related_capec in related_capecs: # scorre capec id correlati
                            for cve_id in cve2capecs:
                                if related_capec in cve2capecs[cve_id]:
                                    file.write(f"   {cve_id}\n")
                else:
                    file.write("\n  X - no mapping available\n")   
                file.write(f"\n")           
            file.write(f"\n\n")

    except IOError as e:
        print(f"Errore durante l'apertura o la scrittura nel file: {e}")
    except Exception as e:
        print(f"Si è verificato un errore inaspettato: {e}")
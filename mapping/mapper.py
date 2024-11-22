import os
import yaml
import json
import xml.etree.ElementTree as ET
import re
from mitreattack.stix20 import MitreAttackData


# Function that extracts all CVE-IDs from a single report file
# Arg:
#    file_path (str): The file path of the report file
# Returns:
#    set: A set of CVE-IDs
def extract_cves(file_path):
    output = set()

    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
        
        for host in data.get("hosts", {}).values():
            output.update(host.get("cves", []))
    
    except yaml.YAMLError as e:
        print(f"  ERROR: Could not parse YAML file {file_path}: {e}")
    except Exception as e:
        print(f"  ERROR: Unexpected error while extracting CVE-IDs from {file_path}: {e}")

    return output


# Function that aggregates the total CVE-IDs from all reports into a single set
# Arg:
#    directory (str): The base directory where report.xml.yml files are stored
# Returns:
#    set: A set of CVE-IDs
def get_all_cves_from_all_scans(directory):
    output = set()

    try:
        for file_name in os.listdir(directory):
            if file_name.endswith('.xml.yml'):
                file_path = os.path.join(directory, file_name)
                cves_single_report = extract_cves(file_path)
                output.update(cves_single_report)

    except FileNotFoundError as e:
        print(f"  ERROR: Directory {directory} not found: {e}")
    except PermissionError as e:
        print(f"  ERROR: Permission denied to access {directory}: {e}")
    except Exception as e:
        print(f"  ERROR: Unexpected error while processing reports in {directory}: {e}")
    
    return output


# Function that maps CVE-IDs to CWE-IDs from the cvelistV5 repository
# Args:
#    cves (set): A set of CVE-IDs.
#    cves_dir (str): The base directory where CVE JSON files are stored
# Returns:
#    dict: A dictionary with CVE-ID as keys and a list of CWE-IDs as values
def get_all_cwes_for_all_cves(cves, directory):
    output = {}

    for cve in cves:
        
        parts = cve.split('-')
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
            continue

        year = parts[1]
        number = parts[2]

        if len(number) > 4:
            n_key = f"{number[:2]}xxx"
        else:
            n_key = f"{number[0]}xxx"

        cve_path = os.path.join(directory, year, n_key, f"{cve}.json")
        if not os.path.exists(cve_path):
            continue

        try:
            with open(cve_path, 'r') as json_file:
                cve_data = json.load(json_file)

            cwe_ids = set()

            problem_types = cve_data.get("containers", {}).get("cna", {}).get("problemTypes", [])
            for problem_type in problem_types:
                for description in problem_type.get("descriptions", []):
                    cwe_id = description.get("cweId")
                    if cwe_id:
                        cwe_ids.add(cwe_id)

            if cwe_ids:
                output[cve] = list(cwe_ids)

        except json.JSONDecodeError as e:
            print(f"  ERROR: Could not parse JSON for {cve} at {cve_path}: {e}")
        except Exception as e:
            print(f"  ERROR: Unexpected error for {cve} at {cve_path}: {e}")

    return output


# Function that extracts all CWE-IDs from the dictionary produced by get_all_cwes_for_all_cves
# Arg:
#    cve_cwes_match (dict): The dictionary with CVE-ID as keys and a list of associated CWE-IDs as values
# Returns:
#    set: A set of CWE-IDs
def extract_cwes(cve_cwes_match):
    output = set()

    for cve, cwes in cve_cwes_match.items():
        output.update(cwes)
    
    return output


# Function that maps CWE-IDs to CAPEC-IDs
# Args:
#    file_path: Path to the 658.xml file
#    cwe_ids: Set of CWE-IDs to search for
# Returns:
#    dict: Dictionary with CWE-ID as keys and a list of associated CAPEC-IDs as values
def get_capec_for_all_cwes(cwes, file_path):
    output = {}
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    c_key = {cwe.split("-")[1] for cwe in cwes}
    
    tree = ET.parse(file_path)
    root = tree.getroot()

    for attack_pattern in root.findall(".//capec:Attack_Patterns/capec:Attack_Pattern", ns):
        capec_id = attack_pattern.attrib.get("ID")

        related_weaknesses = attack_pattern.findall(".//capec:Related_Weakness", ns)
        for weakness in related_weaknesses:
            cwe_id = weakness.attrib.get("CWE_ID")
            if cwe_id in c_key:
                output.setdefault(f"CWE-{cwe_id}", []).append(capec_id)

    return output


# Function to extract all CAPEC-IDs into a single set
# Args:
#    cwe_capecs_match (dict): Dictionary of CWE-ID as a key and CAPEC-IDs as values
# Returns:
#    set: Set with all CAPECE-ID extracted by the input
def extract_capecs(cwe_capecs_match):
    output = set()
    
    for cwe, capecs in cwe_capecs_match.items():
        output.update(capecs)
    
    return output


# Function that maps CAPEC-IDs to ATT&CK TTS-IDs
# Args:
#    capec_ids (set): Dictionary of CWE-ID as a key and CAPEC-IDs as values
# Returns:
#    set: Set with all CAPECE-ID extracted by the input
def get_tts_for_all_capecs(capecs, file_path):
    output = {}
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    try:

        tree = ET.parse(file_path)
        root = tree.getroot()

        for capec_id in capecs:
            tts_ids = []

            attack_pattern = root.find(f".//capec:Attack_Pattern[@ID='{capec_id}']", ns)
            if attack_pattern is not None:

                for taxonomy_mapping in attack_pattern.findall(".//capec:Taxonomy_Mapping[@Taxonomy_Name='ATTACK']", ns):
                    for entry in taxonomy_mapping.findall(".//capec:Entry_ID", ns):
                        tts_id = entry.text.strip()
                        tts_ids.append(tts_id)

            if tts_ids:
                output[capec_id] = tts_ids

    except ET.ParseError as e:
        print(f"ERROR: Could not parse ATT&CK XML file: {e}")
    except FileNotFoundError as e:
        print(f"ERROR: ATT&CK file not found: {e}")
    except Exception as e:
        print(f"ERROR: Unexpected error while processing ATT&CK mapping: {e}")

    return output


# Function that maps CVE-IDs to ATT&CK TTS-IDs
# Args:
#    cve_cwes_match (dict): Mapping of CVE-IDs to CWE-IDs
#    cwe_capecs_match (dict): Mapping of CWE-IDs to CAPEC-IDs
#    capec_tts_match (dict): Mapping of CAPEC-IDs to ATT&CK TTS-IDs
# Returns:
#    dict: Mapping of CVE-IDs to formatted TTS-IDs
def get_tts_for_all_cves(cve_cwes_match, cwe_capecs_match, capec_tts_match):
    output = {}
    
    for cve, cwe_ids in cve_cwes_match.items():
        tts_ids = set()
        
        for cwe_id in cwe_ids:
            capec_ids = cwe_capecs_match.get(cwe_id, [])
            
            for capec_id in capec_ids:
                raw_tts_ids = capec_tts_match.get(capec_id, [])
                
                for tts_id in raw_tts_ids:
                    formatted_tts_id = f"T{tts_id}"
                    tts_ids.add(formatted_tts_id)
        
        if tts_ids:
            output[cve] = tts_ids
    
    return output

# Function that maps CVE-IDs to ATT&CK Matrix TTS-IDs and info
# Args:
#    capec_tts_match (dict): Mapping of CAPEC-IDs to ATT&CK TTS-IDs
#    matrix_file_path (str): ATT&CK Matrix file path
def check_matrix_for_all_cves(cve_tts_match, matrix_file_path):

    output_file="./output.txt"

    mitre_attack_data = MitreAttackData(matrix_file_path)

    techniques = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
    subtechniques = mitre_attack_data.get_subtechniques(remove_revoked_deprecated=True)

    technique_dict = {technique['id']: technique for technique in techniques}
    subtechnique_dict = {subtechnique['id']: subtechnique for subtechnique in subtechniques}

    try:

        with open(output_file, 'w') as file:

            for cve, tts_ids in cve_tts_match.items():
                file.write(f"Vuln-ID: {cve};\n")
                print(f"Vuln-ID: {cve}\n")
        
                
                for technique in techniques:
                    for ref in technique.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            external_id = ref.get('external_id')
                            if external_id in tts_ids:
                                file.write(f"  TTS-ID: {external_id}; Name TTS: {technique.get('name')}; Type: Technique\n")
                                print(f"TTS-ID: {external_id}; Name: {technique.get('name')}; Type: Technique")
        
                for subtechnique in subtechniques:
                    for ref in subtechnique.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            external_id = ref.get('external_id')
                            if external_id in tts_ids:
                                file.write(f"  TTS-ID: {external_id}; Name TTS: {subtechnique.get('name')}; Type: Subtechnique\n")
                                print(f"TTS-ID: {external_id}; Name: {subtechnique.get('name')}; Type: Subtechnique")
                print("\n")
    
    except IOError as e:
        print(f"Errore durante l'apertura o la scrittura nel file: {e}")
    except Exception as e:
        print(f"Si è verificato un errore inaspettato: {e}")
            

# Program entry point
if __name__ == "__main__":
    
    scans_directory = "."
    cves_directory = "./../../cvelistV5/cves"
    capecs_file_path = "./658.xml"
    matrix_file_path="./enterprise-attack.json"
    
    # Phase 1: Extract all CVE-IDs from the .xml.yml reports of scans
    all_cves = get_all_cves_from_all_scans(scans_directory)

    # Phase 2: Search for matching CWE-IDs in the CVE-List directory
    cve_cwes_match = get_all_cwes_for_all_cves(all_cves, cves_directory)

    # Phase 3: Search for matching CWE-IDs in the CAPEC-List2ATT&CK.xml file
    all_cwes = extract_cwes(cve_cwes_match)
    cwe_capecs_match = get_capec_for_all_cwes(all_cwes, capecs_file_path)
    
    # Phase 4: Search for all TTS-IDs for each CAPEC-IDs in the CAPEC-List2ATT&CK.xml file
    all_capecs = extract_capecs(cwe_capecs_match)
    capec_tts_match = get_tts_for_all_capecs(all_capecs, capecs_file_path)

    # Phase 5: Match all TTS-IDs for each CVE-ID
    cve_tts_match = get_tts_for_all_cves(cve_cwes_match, cwe_capecs_match, capec_tts_match)
    
    # Phase 6: Check more info about TTS in the ATT&CK Matrix
    cve_matrix_match = check_matrix_for_all_cves(cve_tts_match, matrix_file_path)
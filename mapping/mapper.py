import os
import yaml
import json
import xml.etree.ElementTree as ET
import re

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

# # Function that retrieves CWE-IDs for each CVE-ID from the cvelistV5 repository
# # Args:
# #    cves (set): A set of CVE-IDs.
# #    cves_dir (str): The base directory where CVE JSON files are stored
# # Returns:
# #    dict: A dictionary with CVE-ID as keys and a list of CWE-IDs as values
def get_all_cwes_for_all_cves(cves, directory):
    output = {}

    # interation on each CVE-ID
    for cve in cves:
        
        parts = cve.split('-')

        # check id format
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
            continue  # skip if invalid

        year = parts[1]
        number = parts[2]

        # determine NXXX folder based on the CVE-ID number length
        if len(number) > 4:
            n_key = f"{number[:2]}xxx"  # extract the first two
        else:
            n_key = f"{number[0]}xxx"  # extract only the first

        # cvelist path construction
        cve_path = os.path.join(directory, year, n_key, f"{cve}.json")

        # check path
        if not os.path.exists(cve_path):
            continue

        try:
            # read and parse the CVE.json file
            with open(cve_path, 'r') as json_file:
                cve_data = json.load(json_file)

            cwe_ids = set()

            problem_types = cve_data.get("containers", {}).get("cna", {}).get("problemTypes", [])
            for problem_type in problem_types:
                for description in problem_type.get("descriptions", []):
                    cwe_id = description.get("cweId")
                    if cwe_id:
                        cwe_ids.add(cwe_id)

            # update results
            if cwe_ids:
                output[cve] = list(cwe_ids)

        except json.JSONDecodeError as e:
            print(f"  ERROR: Could not parse JSON for {cve} at {cve_path}: {e}")
        except Exception as e:
            print(f"  ERROR: Unexpected error for {cve} at {cve_path}: {e}")

    return output


# Function that extracts all CWE-IDs from the dictionary produced by get_all_cwes_for_all_cves
# Arg:
#    cve_cwes_match (dict): The dictionary CVE-ID,CWE-IDs
# Returns:
#    set: A set of CWE-IDs
def extract_cwes(cve_cwes_match):
    print(" CALL: extract_cwe_ids")
    
    output = set()
    for cve, cwes in cve_cwes_match.items():
        output.update(cwes)
    
    return output


# Function that create a dictionary mapping CWE-IDs to CAPEC-IDs
# Args:
#    file_path: Path to the 658.xml file
#    cwe_ids: Set of CWE-IDs to search for
# Returns:
#    dict: Dictionary with CWE-ID as keys and a list of associated CAPEC-IDs as values
def get_capec_for_all_cwes(cwes, file_path):
    
    output = {}
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    # normalize CWE-IDs = remove "CWE-" prefix
    c_key = {cwe.split("-")[1] for cwe in cwes}
    
    # Parse the XML file
    tree = ET.parse(file_path)
    root = tree.getroot()

    # iterate over Attack_Pattern elements = CAPECs
    for attack_pattern in root.findall(".//capec:Attack_Patterns/capec:Attack_Pattern", ns):
        capec_id = attack_pattern.attrib.get("ID")

        # find related weaknesses = CWEs
        related_weaknesses = attack_pattern.findall(".//capec:Related_Weakness", ns)
        # iterate over weaknesses
        for weakness in related_weaknesses:
            cwe_id = weakness.attrib.get("CWE_ID")
            if cwe_id in c_key:
                output.setdefault(f"CWE-{cwe_id}", []).append(capec_id)

    return output


# Program entry point
if __name__ == "__main__":
    
    scans_directory = "."
    cves_directory = "./../../cvelistV5/cves"
    capecs_file_path = "./658.xml"
    
    # Phase 1: Extract all CVE-IDs from the .xml.yml reports of scans
    all_cves = get_all_cves_from_all_scans(scans_directory)

    # Phase 2: Search for matching CWE-IDs in the CVE-List directory
    cve_cwes_match = get_all_cwes_for_all_cves(all_cves, cves_directory)

    # Phase 3: Search for matching CWE-IDs in the CAPEC-List2ATT&CK.xml file
    all_cwes = extract_cwes(cve_cwes_match)

    cwe_capecs_match = get_capec_for_all_cwes(all_cwes, capecs_file_path)
    
    print("\nCWE-ID to CAPEC-ID mapping:")
    for cwe, capecs in cwe_capecs_match.items():
        print(f"{cwe}: {', '.join(capecs)}")
import os
import hashlib
from tqdm import tqdm
import requests

def calculate_file_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def fetch_hashes_from_url(url):
    """Fetch hash signatures from a URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        hashes = set(response.text.splitlines())
        return hashes
    except requests.RequestException as e:
        print(f"Error fetching signature database: {e}")
        return set()

def scan_file(file_path, signature_database):
    """Scan a file against a signature database."""
    file_hash = calculate_file_hash(file_path)

    if file_hash in signature_database:
        return f"File '{file_path}' is infected!"
    else:
        return None

def scan_directory(directory_path, signature_database):
    """Scan all files in a directory."""
    infected_files = []

    for root, dirs, files in tqdm(os.walk(directory_path), desc='Scanning', unit=' files'):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            result = scan_file(file_path, signature_database)
            if result:
                infected_files.append(result)

    return infected_files

if __name__ == '__main__':
  
    signature_database_url = 'https://virusshare.com/hashfiles/VirusShare_00000.md5'

    try:
        
        signature_database = fetch_hashes_from_url(signature_database_url)
        print("Signature database loaded successfully.")


        user_input = input("Enter the path of the file or folder to scan: ")
        path_to_scan = os.path.expanduser(user_input)  
        if os.path.exists(path_to_scan):
            if os.path.isfile(path_to_scan):
                
                result = scan_file(path_to_scan, signature_database)
                if result:
                    print(result)
                else:
                    print("File is clean and has no viruses!")
            elif os.path.isdir(path_to_scan):

                infected_files = scan_directory(path_to_scan, signature_database)
                if infected_files:
                    for infected_file in infected_files:
                        print(infected_file)
                else:
                    print("The folder is safe and has no infected files!")
            else:
                print(f"Invalid input: '{path_to_scan}' is neither a file nor a directory.")
        else:
            print(f"Path '{path_to_scan}' not found.")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")

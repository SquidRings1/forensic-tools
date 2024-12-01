import os
import hashlib
import requests

API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
PREFETCH_DIR = 'path_to_prefetch_directory'

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_virustotal_report(md5):
    url = f'https://www.virustotal.com/api/v3/files/{md5}'
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def scan_prefetch_directory(directory):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.exe') or file.endswith('.pf'):
                file_path = os.path.join(root, file)
                md5 = get_md5(file_path)
                report = get_virustotal_report(md5)
                results.append({
                    'file': file,
                    'md5': md5,
                    'report': report
                })
    return results

def main():
    results = scan_prefetch_directory(PREFETCH_DIR)
    for result in results:
        print(f"File: {result['file']}")
        print(f"MD5: {result['md5']}")
        if result['report']:
            print(f"VirusTotal Report: {result['report']}")
        else:
            print("No report found")
        print()

if __name__ == '__main__':
    main()

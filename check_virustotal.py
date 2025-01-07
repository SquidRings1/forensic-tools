import csv
import requests

API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
CSV_FILE = '20241128_130748_TimelineExplorer_Export.csv'
OUTPUT_FILE = 'virustotal_results.csv'

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

def main():
    with open(CSV_FILE, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        results = []

        for row in reader:
            md5 = row['MD5']
            if md5:
                report = get_virustotal_report(md5)
                if report:
                    row['VirusTotal Report'] = report
                else:
                    row['VirusTotal Report'] = 'No report found'
            results.append(row)

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = reader.fieldnames + ['VirusTotal Report']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
        writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    main()

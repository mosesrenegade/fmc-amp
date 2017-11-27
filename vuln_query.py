#/usr/bin/env python3
import requests
import datetime
import json

with open('amp.json', 'r') as f:
    amp_config = json.load(f)

client_id = amp_config['client_id']
api_key = amp_config['api_key']

start = str(datetime.datetime.now())[:-7]

vuln = '1107296279'
indicator = vuln
url = 'https://{}:{}@api.amp.cisco.com/v1/events?event_type[]={}'.format(client_id,api_key,indicator)

r = requests.get(url)

query = r.json()

total_results = query['metadata']['results']['total']

with open('vulns.csv','w') as f:
        f.write('Date,GUID,Hostname,File Name,SHA256\n')

for n in query['data']:
    date = n['date']
    computer = n['computer']
    guid = computer['connector_guid']
    hostname = computer['hostname']
    external_ip = computer['external_ip']
    file = n['file']
    file_name = file['file_name']
    file_sha256 = file['identity']['sha256']

    print(date,guid,hostname,file_name,file_sha256)
    with open('vulns.csv', encoding='utf-8', mode='a') as f:
        f.write('{},{},{},{},{}\n'.format(date,guid,hostname,file_name,file_sha256))

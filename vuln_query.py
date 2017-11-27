import requests
import datetime

start = str(datetime.datetime.now())[:-7]

# 3rd Party API Client ID
client_id = 'asdf1234qwer1234asdf'

# API Key
api_key = 'asdf1234-qwer-1234-asdf-1234asdf1234'


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
    with open('vulns.csv','a') as f:
        f.write('{},{},{},{},{}\n'.format(date,guid,hostname,file_name,file_sha256))



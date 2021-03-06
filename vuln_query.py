#/usr/bin/env python3
import requests
import datetime
import json
import pprint

######################
# Setup Variables
######################

debug=1
pp = pprint.PrettyPrinter(indent=4)

with open('amp.json', 'r') as f:
    amp_config = json.load(f)

client_id = amp_config['client_id']
api_key = amp_config['api_key']
start = str(datetime.datetime.now())[:-7]

######################
# Let's get Vulns
######################

def GetVulns():
    try:
        #This is a static value, it would be best if we could have the system automatically find this value instead of inserting a static value.
        vuln = '1107296279'
        indicator = vuln
        url = 'https://{}:{}@api.amp.cisco.com/v1/events?event_type[]={}'.format(client_id,api_key,indicator)
        response = requests.get(url)
        results = response.json()
        total_results = results['metadata']['results']['total']
        return(results)
    except requests.exceptions.RequestException as e:
        return "Error: {}".format(e)

def printDict(query):
    for k, v in query.items():
        if type(v) is dict:
            #printDict(v)
            return(query)
        else:
            #print("{0} : {1}".format(k, v))
            return(query)
if __name__ == "__main__":

    query = GetVulns()

    if debug:
        print = pp.pprint

    event_types = {}
    for json_data in query["data"]:

        for g in json_data["computer"]:
            print("{}:{}".format(guid, value))
            exit()

    for e_id in query["data"]:
        event_types["guid"] = e_id["id"]
        event_types["computer"] = e_id["computer"]
        for f_id in e_id["files"]:
            event_type["files"] = f_id["files"]
            for g_id in event_types["files"]:
                event_types["vulnerabilties"] = g_id["vulnerabilities"]

    for key,value in event_types.items():
        if debug:
            print("{}:{}".format(value,key))

    with open('query-debug.csv', 'wt') as out:
        json.dump(query, out, indent=4)
    #json_dict = {}
    #json_query = json.dumps(query, indent = 2)
    #json_load = json.loads(json_query)
    #for json_dict in query:
        #for key,value in json_dict.iteritems():
            #print("key: {key} | value: {value}".format(key=key, value=value))
    exit()

    #json_query = json.dumps(query, indent = 2)
    if debug:
        print(computer)

    with open('vulns.csv','w') as f:
        f.write('Date,GUID,Hostname,File Name,SHA256\n')

    for n in json_load['data']:
        date = n['date']
        computer = n['computer']
        guid = computer['connector_guid']
        hostname = computer['hostname']
        external_ip = computer['external_ip']
        file = n['file']
        file_name = file['file_name']
        file_sha256 = file['identity']['sha256']
        vulnerability = n['vulnerabilities']

    exit()
    if debug:
      print(date,guid,hostname,file_name,file_sha256)

    with open('vulns.csv', encoding='utf-8', mode='a') as f:
        f.write('{},{},{},{},{}\n'.format(date,guid,hostname,file_name,file_sha256))

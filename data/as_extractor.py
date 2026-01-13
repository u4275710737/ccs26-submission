import json
import os
import IP2Location

from ipwhois import IPWhois
from tqdm import tqdm

DIR_WITH_DATA = "daily_scans"
DAY_ANALYSIS = "echo_results_2025-06-14"
COUNTRY_RESTRICTION = ""

ipsToAnalyze = []
try:
    with open("ips_left.json", 'r') as f:
        ipsToAnalyze = json.load(f)
except FileNotFoundError:
    # Extract TCP and UDP first scan day to list
    # If Country flag is set, run through DB and filter for IPs from that country first
    
    if COUNTRY_RESTRICTION != "":
        database = IP2Location.IP2Location("IP2LOCATION-LITE-DB5.BIN", "SHARED_MEMORY")

    for filename in sorted(os.listdir(DIR_WITH_DATA + "/tcp")):  # loops from oldest to latest
        if filename.count("_") == 3 or not filename.startswith("echo_results") or DAY_ANALYSIS not in filename:  # only use daily scans here
            continue

        # extract TCP
        with open(os.path.join(DIR_WITH_DATA + "/tcp", filename), 'r') as f:
            results = json.load(f)

        for result in tqdm(results):
            if result['result'] == "WORKING":
                working_ip = result['echoIP']['address']
                if COUNTRY_RESTRICTION != "":
                    rec = database.get_all(working_ip)
                    country = rec.country_short
                    if country == COUNTRY_RESTRICTION:
                        ipsToAnalyze.append(working_ip)
                else:
                    ipsToAnalyze.append(working_ip)
                
        # extract UDP
        with open(os.path.join(DIR_WITH_DATA + "/udp", filename), 'r') as f:
            results = json.load(f)

        for result in tqdm(results):
            if result['result'] == "WORKING":
                working_ip = result['echoIP']['address']
                if COUNTRY_RESTRICTION != "":
                    rec = database.get_all(working_ip)
                    country = rec.country_short
                    if country == COUNTRY_RESTRICTION and working_ip not in ipsToAnalyze:
                        ipsToAnalyze.append(working_ip)
                else:
                    if working_ip not in ipsToAnalyze:
                        ipsToAnalyze.append(working_ip)
try:
    with open(f"as_dict_{COUNTRY_RESTRICTION}.json", 'r') as f:
        asDict = json.load(f)
except FileNotFoundError:
    asDict = None

print("Analyzing ASes IPs for first scan day...")
if asDict is None:
    asDict = {}
ipsLeft = []
for ip in tqdm(ipsToAnalyze):
    obj = IPWhois(str(ip))
    res = None
    while True:
        try:
            res = obj.lookup_rdap()
            break
        except:
            print(f"RDAP Lookup Error for IP {ip}... trying whois")
            try:
                res = obj.lookup_whois()
                break
            except:
                print(f"Whois Lookup Error for IP {ip}... ignoring...")
                ipsLeft.append(ip)
                break
    if res is not None:
        asn = res["asn"]
        if asn not in asDict:
            asDict[asn] = [1, res["asn_description"], [ip]]
        else:
            asDict[asn][0] += 1
            asDict[asn][2].append(ip)

print(f"First scan day ASes: {len(asDict)}")
print(f"IPs left to analyze: {len(ipsLeft)}")

with open(f"as_dict_{COUNTRY_RESTRICTION}.json", 'w') as f:
    json.dump(asDict, f)

with open("ips_left.json", 'w') as f:
    json.dump(ipsLeft, f)

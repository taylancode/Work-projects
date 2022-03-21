import requests
import sys
import xml.etree.ElementTree as ET
import csv
import time
import itertools
import threading
requests.packages.urllib3.disable_warnings()

def get_rules(dgrp):

    try:
        r = requests.post(f"https://{fw}/api/?key={key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/post-rulebase/security", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)

            # Iterate over every rule in device group
            for i in root.findall("./result/security/rules/entry"):

                # Get the rule name
                rname = i.get("name")

                # Get all members in destination field
                for destinations in i.findall('./destination/member'):

                    dest = destinations.text
                    
                    # Returns True if destination address contains search_obj 
                    if dest == search_obj:

                        dest_true = True
                        break

                    else:

                        dest_true = False
                
                for sources in i.findall('./source/member'):

                    source = sources.text

                    # Returns True if source address contains search_obj 
                    if source == search_obj:

                        src_true = True
                        break
                    
                    else:

                        src_true = False
                
                # If search_obj is in source address or destination address, call function to gather info and write to csv
                if dest_true is True or src_true is True:

                    get_rule_info(rname)


        else:
            print("API call failed, please check API key is correct")
            sys.exit()

    except:
        pass

# Called via get_rules function once condiiton is met
def get_rule_info(rname):

    # Lists to be appended to 
    source_zone_list = []
    dest_zone_list = []
    source_addr_list = []
    dest_addr_list = []
    source_user_list = []
    app_list = []
    service_list = []


    try:

        # API call to gather information for rule
        r = requests.post(f"https://{fw}/api/?key={key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/post-rulebase/security/rules/entry[@name='{rname}']", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)

            # Extract and append information from rule to be written to csv
            for sources in root.findall('.result/entry/source/member'):
                source = sources.text
                source_addr_list.append(source)

            for sourcezones in root.findall('.result/entry/from/member'):
                src_zone = sourcezones.text
                source_zone_list.append(src_zone)

            for destzones in root.findall('.result/entry/to/member'):
                dest_zone = destzones.text
                dest_zone_list.append(dest_zone)

            for sourceusers in root.findall('.result/entry/source-user/member'):
                user = sourceusers.text
                source_user_list.append(user)

            for destinations in root.findall('.result/entry/destination/member'):
                dest = destinations.text
                dest_addr_list.append(dest)

            for apps in root.findall('.result/entry/application/member'):
                app = apps.text
                app_list.append(app)

            for services in root.findall('.result/entry/service/member'):
                service = services.text
                service_list.append(service)

            # Writes the lists into csv 
            resultWriter.writerow([dgrp, rname, source_user_list, source_zone_list, source_addr_list, dest_zone_list, dest_addr_list, app_list, service_list])

    except:
        pass

def animate():

    print("\n")
    for c in itertools.cycle(['|', '/', '-', '\\']): 
        if done:
            break
        sys.stdout.write(f"\rGathering rules, please wait {c}")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write(f"\rComplete, find the results in Rules-{search_obj}.csv")
    print("\n")

if __name__ == '__main__':

    # Defining Panorama IP and device groups
    print("Enter Panorama IP/FQDN:")
    fw = input("> ")
    dgrp_list = [] #List of device groups

    # Get User input variables
    print("\nEnter object name")
    search_obj = input('> ')
    print("Enter API key")
    key = input('> ')

    # Create CSV file to be written to
    result_log=("Rules-"+search_obj+".csv")
    resultcsv = open(result_log,'w', newline='')
    resultWriter = csv.writer(resultcsv, delimiter=',')
    resultWriter.writerow(["Device Group","Rule Name","Src_User", "Src_Zone","Src_Addr", "Dest_Zone", "Dest_Addr", "Application", "Service ports"])

    # Threading for the loading animation
    done = False
    t = threading.Thread(target=animate)
    t.start()

    # Calls get_rules function for each device group in the list
    for each in dgrp_list:
        dgrp = each
        
        get_rules(dgrp)
    
    # Ends animation and closes result file
    done = True
    resultcsv.close()
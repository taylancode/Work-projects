#Import modules
import requests
import xml.etree.ElementTree as ET
import sys

#Disable urllib warnings
requests.packages.urllib3.disable_warnings()

#Gets all existing URL filtering profiles in specified device group and appends to list
def getprofiles(fwip, key):

    try:
        #API call to get list of all URL filtering profiles in specified device group
        r = requests.post(
            f"https://{fwip}/api/?key={key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/profiles/url-filtering", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #Iterates over XML, gets the name of each profile and appends to list
            for entry in root.findall("./result/url-filtering/entry"):
                names = entry.get('name')
                urlpfiles.append(names)
    except:
        print("API call failed, please check connectivity is good and API key is correct.")

#Iterates over every security rule and URL filtering member
#If any URL filtering profile is found, appends to list 
def getsecrules(fwip, key):

    try:
        r = requests.post(
            f"https://{fwip}/api/?key={key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/post-rulebase/security", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #Iterating over every rule and every URL filtering member of each rule
            for i in root.findall("./result/security/rules/entry"):
                for rule in i.findall('./profile-setting/profiles/url-filtering/member'):
                    rules = rule.text
                    
                    if rules != None:
                        secrules.append(rules)

                    else:
                        continue

    except:
        print("API call failed, please check connectivity is good and API key is correct.")


if __name__ == '__main__':

    #Gather variables
    print("Enter Panorama IP/FQDN:")
    fwip = input("> ")
    print("Enter Device Group:")
    dgrp = input("> ")
    print("Enter API Key: ")
    key = input("> ")

    #Lists to be appended to
    urlpfiles = []
    secrules = []
    unused = []

    #To count how many profiles are unused
    count = 0

    #Calls the functions
    getprofiles(fwip, key)
    getsecrules(fwip, key)

    #If profile exists in the secrules list it means that it's used since it has been found in a rule
    #If not found in secrules list, appends profile name to unused list
    for profile in urlpfiles:
        ifcat = any(i in str(profile) for i in secrules)

        if ifcat is False:
            unused.append(profile)

    #Writes all outputs in unused list to text file, prints output if list is empty
    with open('unused.txt', 'w') as f:

        if not unused:
            print("\nNo unused profiles")

        else:
            for i in unused:
                f.write(i)
                f.write('\n')
                count += 1
            print("\n"+str(count)+" unused profiles added to list")


    f.close()
    sys.exit()

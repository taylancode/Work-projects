#Import modules
import requests
import xml.etree.ElementTree as ET
import sys

#Disable urllib warnings
requests.packages.urllib3.disable_warnings()

#Gets all existing URL categories in specific device group
def getcategories(fwip, key):

    try:
        #API call to get all existing URL categories in device group
        r = requests.post(
            f"https://{fwip}/api/?key={key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/profiles/custom-url-category", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)
            
            #Iterate over XML and append all names to list
            for entry in root.findall("./result/custom-url-category/entry"):
                names = entry.get('name')
                urlcats.append(names)
    except:
        print("API call failed, please check connectivity is good and API key is correct.")

#Gets all members of every URL filtering profile 
def getprofiles(fwip, key):

    try:
        #API call displays all URL filtering profiles of device group and their category members
        r = requests.post(
            f"https://{fwip}/api/?key={key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/profiles/url-filtering", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #If category exists, it will be in one of these lists. Lists are appended to be iterated over later
            for entry in root.findall("./result/url-filtering/entry"):
                for blocked in entry.findall(".block/member"):
                    blockedpfiles = blocked.text
                    pfilecat.append(blockedpfiles)
                for alert in entry.findall(".alert/member"):
                    alertpfiles = alert.text
                    pfilecat.append(alertpfiles)
                for cont in entry.findall(".continue/member"):
                    contpfiles = cont.text
                    pfilecat.append(contpfiles)
    except:
        print("API call failed, please check connectivity is good and API key is correct.")

#Iterates over all security rules and appends URL category members if one/more is specified
def getsecrules(fwip, key):

    try:
        #API call to gather all security rules to be iterated over
        r = requests.post(
            f"https://{fwip}/api/?key={key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/post-rulebase/security", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #Iterates over XML data to find URL category members
            for i in root.findall("./result/security/rules/entry"):
                for rule in i.findall('./category/member'):
                    rules = rule.text

                    #Appends to list if any are found
                    if rules != 'any':
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
    pfilecat = []
    secrules = []
    urlcats = []
    unused = []

    #To count unused categories
    count = 0

    #Calling every function
    getcategories(fwip, key)
    getprofiles(fwip, key)
    getsecrules(fwip, key)

    #For every existing category, it checks if it exists in any rule or url profile
    #If it doesn't exist, it will append to unused list
    for cat in urlcats:
        ifrule = any(i in str(cat) for i in secrules)
        ifurlprofile = any(i in str(cat) for i in pfilecat)

        if ifrule is False:
            if ifurlprofile is False:
                unused.append(cat)

    #Write all unused categories to text file, prints output if unused list is empty
    with open('unusedcat.txt', 'w') as f:

        if not unused:
            print("\nNo unused categories")

        else:
            for i in unused:
                f.write(i)
                f.write('\n')
                count += 1
            print("\n"+str(count)+" unused categories added to list")


    f.close()
    sys.exit()
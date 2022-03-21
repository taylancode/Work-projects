import requests
import xml.etree.ElementTree as ET
import sys
import csv
import threading
import datetime
import re
import getpass
from apigen import get_key
requests.packages.urllib3.disable_warnings()

def create_new_tag(fw, key, tag):

    #Create new tag
    r = requests.post(f"https://{fw}/api/?type=config&action=set&key={key}&xpath=/config/shared/tag/entry[@name='Unused - {tag}']&element=<color>color2</color>", verify=False)

    if r.status_code == 200:
        
        root = ET.fromstring(r.text)

        if root.get("status") == "success":
            print("\nCreated tag, proceeding..")
        else:
            print("\nCould not create tag, exiting..")
            sys.exit()

    else:
        print("\nCould not create tag, exiting..")
        sys.exit()

def get_unused_rules (fw, key, dgrp, ticket):

    #Pulls all unused rules
    r = requests.post(f"https://{fw}/api/?key={key}&type=op&cmd=<show><rule-hit-count><device-group><entry name='{dgrp}'><post-rulebase><entry name='security'><rules><all/></rules></entry></post-rulebase></entry></device-group></rule-hit-count></show>",verify=False)

    if r.status_code == 200:
        root = ET.fromstring(r.text)

        unusedrules = []

        # Get all rule names
        for i in root.findall("./result/rule-hit-count/device-group/entry/rule-base/entry/rules/"):
            rname = i.get("name")
            state = i.find("rule-state").text

            #Append unused rules to list
            if state == 'Unused':
                unusedrules.append(rname)

        #Tag rules and write to csv
        for rule in unusedrules:
            unused = rule

            if any(i in unused for i in ignorelist) is True:
                pass

            else:

                addtag = requests.post(f"https://{fw}/api/?key={key}&type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/post-rulebase/security/rules/entry[@name='{unused}']/tag&element=<member>Unused - {tag}</member>",verify=False)

                if addtag.status_code == 200:

                    root = ET.fromstring(addtag.text)

                    if root.get("status") == "success":

                        resultWriter.writerow([unused, dgrp])

                        addcomment = requests.post(f"https://{fw}/api/?key={key}&type=op&cmd=<set><audit-comment><xpath>/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dgrp}']/post-rulebase/security/rules/entry[@name='{unused}']</xpath><comment>{ticket}</comment></audit-comment></set>", verify=False)

if __name__ == '__main__':

    #Defining variables
    tag = datetime.datetime.now().strftime("%d/%m/%y")
    print(f"Enter Panorama IP/FQDN:")
    fw = input("> ")
    print(f"Enter Username and PW for {fw}")
    print("Username:")
    user = input("> ")
    print("Password:")
    pw = getpass.getpass("> ")

    key = get_key.generate(fw, user, pw)

    print("\nEnter CHG or RITM number")

    #Regex check to ensure correct service now ticket has been entered
    while True:

        ticket = input("> ")

        audit = bool(re.match("(CHG|RITM|INC)[0-9]{7}", ticket))

        if audit == True:
            break
        else:
            print("\nThat's not a valid snow ticket, the format should be CHG/RITM/INC followed by 7 digits")

    #Pull device groups from text file and append to list
    dgrptxt = open('dgrp.txt', 'r')
    dgrp = dgrptxt.readlines()
    dgrptxt.close()
    dgrplist = []
    for each in dgrp:
        dgrplist.append(each.strip("\r\n"))

    #Pulls rules from ignorelist
    ignoretxt = open('ignorelist.txt', 'r')
    ignore = ignoretxt.readlines()
    ignoretxt.close()
    ignorelist = []
    for each in ignore:
        ignorelist.append(each.strip("\r\n"))

    #List to manage multithread
    proclist = []

    #Creating csv to add results and send email
    result_log=("TaggedRules-" + datetime.datetime.now().strftime("%d-%m-%Y") + ".csv")
    resultcsv = open(result_log,'w', newline='')
    resultWriter = csv.writer(resultcsv, delimiter=',')
    resultWriter.writerow(["Tagged Rule","Device Group"])

    create_new_tag(fw, key, tag)

    #Creates a new thread for each device group
    for i in dgrplist:
        dgrp = i
        proc = threading.Thread(target=get_unused_rules, args=[fw, key, dgrp, ticket])
        proc.start()
        proclist.append(proc)

    # Wait for Thread to finish
    for x in proclist:
        x.join()

    print(f"\nTagging complete, please commit to Panorama. You can find results in {result_log}")

    #Close csv, send email, exit script
    resultcsv.close()

    sys.exit()
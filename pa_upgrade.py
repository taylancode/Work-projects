import sys
import xml.etree.ElementTree as ET
import requests
import csv
import time
import ping3
import getpass
import threading

#Ignores SSL warnings
requests.packages.urllib3.disable_warnings()

#Function to authenticate fw with user/pw provided and obtain the API key
def authenticate(fwip, user, pw):

    #Calls the API with specific XPath. Can be found via the Firewall API GUI or CLI
    try:
        r = requests.post(f"https://{fwip}/api/?type=keygen&user={user}&password={pw}", verify=False)

        #Parse XML to be extracted
        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #Takes the value from <result><key><result/><key/> and assigns it to variable
            api_key = root.find(".result/key").text

        else:
            resultWriter.writerow([fwip, "Failed", "Authentication failed"])
            sys.exit()

    except (ConnectionError, TimeoutError) as e:
        resultWriter.writerow([fwip, "Failed", e])
        sys.exit()

    return api_key

#Does a Check now for software on Firewall
def softwarecheck(fwip, api_key):

    #Calls the API with specific XPath. Can be found via the Firewall API GUI or CLI
    try:
        r = requests.post(
            f"https://{fwip}/api/?key={api_key}&type=op&cmd=<request><system><software><check></check></software></system></request>", verify=False)

        #Parse XML to be extracted
        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #Create empty list to be appended to
            vsn = []

            #Finds all versions available after check and appends to list###
            for entry in root.findall(".result/sw-updates/versions/entry"):
                ver = entry.find("version").text
                vsn.append(ver)

            #Looks in the list and finds any value that matches the entered version by the user
            ifver = any(i in str(vers) for i in vsn)

            #If it finds the version requested, it will output the below and continue
            if ifver is True:
                pass

            #If it doesn"t find the version requested, it will output the below and end
            else:
                resultWriter.writerow([fwip, "Failed", f"Could not find version specified. \nCheck connectivity to update servers and that the firewall supports version: {vers}"])
                sys.exit()

        else:
            resultWriter.writerow([fwip, "Failed", "API call failed, ensure that the firewall ip and api key are correct."])
            sys.exit()

    except (ConnectionError, TimeoutError) as e:
        resultWriter.writerow([fwip, "Failed", e])
        sys.exit()


#Initiate the download of the software
def download_software(fwip, api_key, vers):

    #Calls the API with specific XPath. Can be found via the Firewall API GUI or CLI
    try:
        r = requests.post(
            f"https://{fwip}/api/?key={api_key}&type=op&cmd=<request><system><software><download><version>{vers}</version></download></software></system></request>", verify=False)

        #Parse XML to be extracted
        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #Finds the attribute associated to status
            resp = root.attrib
            rstat = resp.get("status")

            #If it returns success, it will continue the script and wait for the job to finish
            if rstat == "success":

                #Finds the jobid
                for job in root.findall("./result"):
                    jobid = job.find("job").text

                    jobstat = "PEND"

                    #While loop to check the job every 1 minute until job is finished
                    while jobstat == "PEND":

                        try:
                            r = requests.post(f"https://{fwip}/api/?key={api_key}&type=op&cmd=<show><jobs><id>{jobid}</id></jobs></show>", verify=False)

                            if r.status_code == 200:
                                root = ET.fromstring(r.text)

                            for stat in root.findall(".result/job"):
                                jobstat = stat.find("result").text
                                time.sleep(60)

                        except (ConnectionError, TimeoutError) as e:
                            resultWriter.writerow([fwip, "Failed", e])
                            sys.exit()

                    else:
                        continue

            else:
                #If the download returns failed, prints the error message and retrys in 1 minute
                # TODO: Add a timeout here
                time.sleep(60)
                download_software(fwip, api_key, vers)

    except (ConnectionError, TimeoutError) as e:
        resultWriter.writerow([fwip, "Failed", e])
        sys.exit()

#Function to initiate install of software
def install_software(fwip, api_key, vers):

    #Calls the API with specific XPath. Can be found via the Firewall API GUI or CLI
    try:
        r = requests.post(
            f"https://{fwip}/api/?key={api_key}&type=op&cmd=<request><system><software><install><version>{vers}</version></install></software></system></request>", verify=False)

        #Parse XML to be extracted
        if r.status_code == 200:
            root = ET.fromstring(r.text)

            #Finds the attribute associated to status
            resp = root.attrib
            rstat = resp.get("status")

            #If it returns success, it will continue the script and wait for the job to finish
            if rstat == "success":

                #Finds the jobid
                for job in root.findall("./result"):
                    jobid = job.find("job").text

                    jobstat = "PEND"

                    #While loop to check the job every 1 minute until job is finished
                    while jobstat == "PEND":

                        try:
                            r = requests.post(f"https://{fwip}/api/?key={api_key}&type=op&cmd=<show><jobs><id>{jobid}</id></jobs></show>", verify=False)

                            if r.status_code == 200:
                                root = ET.fromstring(r.text)

                                for stat in root.findall(".result/job"):
                                    jobstat = stat.find("result").text
                                    time.sleep(60)

                        except (ConnectionError, TimeoutError) as e:
                            resultWriter.writerow([fwip, "Failed", e])
                            sys.exit()

                    else:
                        continue

            else:
                # TODO: Add a timeout here
                time.sleep(60)
                install_software(fwip, api_key, vers)


    except (ConnectionError, TimeoutError) as e:
        resultWriter.writerow([fwip, "Failed", e])
        sys.exit()

#Initiates the reboot
def rbfw(fwip, api_key):

    # Calls the API with specific XPath. Can be found via the Firewall API GUI or CLI
    # A timeout is specified here because it doesn"t return any output
    try:
        requests.post(f"https://{fwip}/api/?key={api_key}&type=op&cmd=<request><restart><system></system></restart></request>", verify=False, timeout=5)

    except:
        pass

#Pings the firewall to check if it is back online
def checkfw(fwip):

    timeout = 0
    time.sleep(600)
    check = ping3.ping(fwip)

    #ping3 returns None if there is no response from the IP
    while check == None:
        time.sleep(60)
        check = ping3.ping(fwip)
        timeout += 1

        if timeout == 30:
            resultWriter.writerow([fwip, "Failed", "No response from firewall after 40 minutes"])
            break

#Checks the version after reboot to ensure it booted to the correct version
def verify(fwip, api_key):

    try:

        r = requests.post(f"https://{fwip}/api/?key={api_key}&type=op&cmd=<show><system><info></info></system></show>", verify=False)

        if r.status_code == 200:
            root = ET.fromstring(r.text)
            panos_ver = root.find(".result/system/sw-version").text

            if panos_ver == vers:
                resultWriter.writerow([fwip, "Success", None])

            else:
                resultWriter.writerow([fwip, "Failed", "Verification failed, firewall did not upgrade to version requested."])

    except:
        # TODO: Add a timeout here
        time.sleep(120)
        verify(fwip, api_key)

#Calls all the functions in specific order
def process(fwip):

        api_key = authenticate(fwip, user, pw)
        softwarecheck(fwip, api_key)
        download_software(fwip, api_key, vers)
        install_software(fwip, api_key, vers)
        rbfw(fwip, api_key)
        checkfw(fwip)
        verify(fwip, api_key)

if __name__ == "__main__":

    #Warning message
    print("***********************************************************************************************************")
    print("***********************************************************************************************************")
    print("***********************************************************************************************************")
    print("***********************************************************************************************************")
    print("***********************WARNING: THIS SCRIPT WILL REBOOT THE SELECTED FIREWALLS*****************************")
    print("***********************************************************************************************************")
    print("***********************************************************************************************************")
    print("***********************************************************************************************************")
    print("***********************************************************************************************************")

    #Variables and user inputs
    fw = input("\nEnter the IP/FQDNs of the firewalls in fw.txt: ")
    vers = input("\nEnter the PanOS version you wish to upgrade to: ")
    user = input("\nEnter your username: ")
    pw = getpass.getpass("\nEnter your password: ")
    proclist = []
    result = []

    #Get all firewalls from list
    if fw == "":
        fwtxt = open("fw.txt", "r")
        fw = fwtxt.readlines()
        fwtxt.close()

    fwlist = []

    for each in fw:
        fwlist.append(each.strip("\r\n"))

    #Creating new csv to add logs
    result_log="PA-Upgrade-Results.csv"
    resultcsv = open(result_log,"w", newline="")
    resultWriter = csv.writer(resultcsv, delimiter=",")
    resultWriter.writerow(["Firewall","Status","Error"])

    #Starts multithreading
    for ip in fwlist:
        fwip = ip
        proc = threading.Thread(target=process, args=[fwip])
        proc.start()
        proclist.append(proc)

    #Wait for Thread to finish
    for x in proclist:
        x.join()

    #Prompt to end
    input(f"\n\n\nScript complete, results can be found in {result_log} \nPlease press enter to close.")

    #Ends script
    resultcsv.close()
    sys.exit()



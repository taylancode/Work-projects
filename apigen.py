import requests
import sys
import getpass
import xml.etree.ElementTree as ET
from colours import style

requests.packages.urllib3.disable_warnings()

'''
Script can be run standalone or imported as a module (Needs colours.py along with it)
Generates API key for any Palo Alto firewall
'''

class get_key():

    def generate(fw, user, pw):

        print("\nRetrieving API key...")

        try:
            
            #API call to firewall with arguments 
            r = requests.post(f'https://{fw}/api/?type=keygen&user={user}&password={pw}', verify=False)
            
            #Gets key from XML data
            if r.status_code == 200:
                root = ET.fromstring(r.text)
                api_key = root.find(".result/key").text

            else:
                print(style.RED + "\nIncorrect credentials." + style.RESET)
                sys.exit()

        except:
            print(style.RED + "\nCould not retrieve API key" + style.RESET)
            sys.exit()
        
        #Returns API key
        return api_key

#Runs when called as a standalone script
#Takes the firewall IP/FQDN as an argument
if __name__ == '__main__':
    
    fw = str(sys.argv[1])
    print(f"\nPlease enter username for {fw}")
    user = input("> ")
    print(f"Please enter password for {fw}")
    pw = getpass.getpass("> ")
    
    key = get_key.generate(fw, user, pw)
    print(style.GREEN + "\nKey: " + style.RESET + key)
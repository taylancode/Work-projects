import requests
import sys
import getpass
import xml.etree.ElementTree as ET
from colours import style

requests.packages.urllib3.disable_warnings()

class get_key():

    def generate(fw, user, pw):

        print("\nRetrieving API key...")

        try:
            
            r = requests.post(f'https://{fw}/api/?type=keygen&user={user}&password={pw}', verify=False)
            
            if r.status_code == 200:
                root = ET.fromstring(r.text)
                api_key = root.find(".result/key").text

            else:
                print(style.RED + "\nIncorrect credentials." + style.RESET)
                sys.exit()

        except:
            print(style.RED + "\nCould not retrieve API key" + style.RESET)
            sys.exit()
        
        return api_key

if __name__ == '__main__':

    fw = str(sys.argv[1])
    print(f"\nPlease enter username for {fw}")
    user = input("> ")
    print(f"Please enter password for {fw}")
    pw = getpass.getpass("> ")
    
    key = get_key.generate(fw, user, pw)
    print(style.GREEN + "\nKey: " + style.RESET + key)
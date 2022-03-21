# Work-projects

Some scripts that I've built for work. Not all were shared due to sensitive data within the script.

All scripts are built in Python for use with Palo Alto Firewalls using their XML API.

## Script information:

- **Tag_Unused.py**: Creates a tag with current date, goes through all security rules in defined device groups and tags the unused rules. This is to aid with cleaning up old rules on the Palo Alto management device (Panorama).

- **apigen.py**: API key generator for Palo Alto firewalls, can be imported or run as a standalone script. 

- **colours.py**: Used in apigen.py just for visibility enhancement.

- **pa_upgrade.py**: Upgrade the software on as many Palo Alto firewalls as you want simultaneously. (Doesn't support HA devices).

- **rule_finder.py**: Searches a specific object and finds all associated rules if any. Gets rule information and creates csv with findings.

- **unused_url_category.py**: Another cleanup script for the Palo Alto management device. Finds all unused URL categories.

- **unused_url_filtering.py**: Another cleanup script for the Palo Alto management device. Finds all unused URL filtering profiles.

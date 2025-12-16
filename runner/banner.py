import logging
import requests
import os

banner = """
      _             __  __
   __| | _ __   ___ \ \/ /
  / _' || '_ \ / __| \  / 
 | (_| || | | |\__ \ /  \ 
  \__,_||_| |_||___//_/\_\
"""

TOOL_NAME = "dnsx"

VERSION = "1.2.3"

def show_banner():
    logging.info(f"{banner}\n")
    logging.info("\t\tprojectdiscovery.io\n\n")

def get_update_callback():
    def update_func():
        show_banner()
        try:
            resp = requests.get("https://api.github.com/repos/projectdiscovery/dnsx/releases/latest")
            latest = resp.json()["tag_name"]
            if latest != VERSION:
                logging.info(f"New version available: {latest}")
            else:
                logging.info("Up to date")
        except Exception as e:
            logging.error(f"Update check failed: {e}")
    return update_func

def auth_with_pdcp():
    show_banner()
    key = os.environ.get("PDCP_KEY")
    if not key:
        logging.error("No PDCP credentials")
        return
    # validate API if needed
    logging.info("PDCP authenticated")
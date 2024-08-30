import emulator_utils 
import sys
sys.path.insert(0, emulator_utils.get_sdk_folder)

# Ahora importa las clases desde tu archivo sdk.py
from sdk import CAPIFProviderConnector
def offboard_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=emulator_utils.get_config_file())

    capif_connector.offboard_and_deregister_nef()
    print("COMPLETED")

    

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    offboard_capif_nef_connector()

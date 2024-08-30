
import emulator_utils 
import sys
sys.path.insert(0, emulator_utils.get_sdk_folder)

# Ahora importa las clases desde tu archivo sdk.py
from sdk import CAPIFInvokerConnector



def showcase_capif_connector():
    """
        This method showcases how one can use the CAPIFConnector class.
        
    """

    capif_connector = CAPIFInvokerConnector(config_file=emulator_utils.get_config_file())

    capif_connector.register_and_onboard_Invoker()
    print("COMPLETED")

if __name__ == "__main__":
    #Let's register invoker to CAPIF. This should happen exactly once
    showcase_capif_connector()




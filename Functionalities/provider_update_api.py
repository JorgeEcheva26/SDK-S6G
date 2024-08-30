import emulator_utils 
import sys
sys.path.insert(0, emulator_utils.get_sdk_folder)

# Ahora importa las clases desde tu archivo sdk.py
from sdk import CAPIFProviderConnector
def showcase_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=emulator_utils.get_config_file())

    capif_connector.update_service(
        service_api_description_json_full_path=emulator_utils.provider_exposer_get_sample_api_description_path())
    print("COMPLETED")

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    showcase_capif_nef_connector()

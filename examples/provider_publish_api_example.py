from evolved5g.sdk import CAPIFProviderConnector
import emulator_utils
def showcase_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=emulator_utils.get_config_file())

    capif_connector.publish_services(
        service_api_description_json_full_path=emulator_utils.nef_exposer_get_sample_api_description_path())
    print("COMPLETED")

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    showcase_capif_nef_connector()

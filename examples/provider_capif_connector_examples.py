from evolved5g.sdk import CAPIFProviderConnector
import capif_exposer_utils

def showcase_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=capif_exposer_utils.get_provider_config_file())

    capif_connector.register_and_onboard_provider()

    capif_connector.publish_services(
        service_api_description_json_full_path=capif_exposer_utils.nef_exposer_get_sample_api_description_path())
    print("COMPLETADO")

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    showcase_capif_nef_connector()

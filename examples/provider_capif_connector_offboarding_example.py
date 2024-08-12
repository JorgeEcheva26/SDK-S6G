from evolved5g.sdk import CAPIFProviderConnector
import capif_exposer_utils

def offboard_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=capif_exposer_utils.get_provider_config_file())

    capif_connector.offboard_and_deregister_nef()
    print("COMPLETADO")

    

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    offboard_capif_nef_connector()

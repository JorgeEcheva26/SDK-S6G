from evolved5g.sdk import CAPIFProviderConnector
import emulator_utils
def showcase_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=emulator_utils.get_config_file())

    capif_connector.register_and_onboard_provider()

    
    print("COMPLETADO")

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    showcase_capif_nef_connector()

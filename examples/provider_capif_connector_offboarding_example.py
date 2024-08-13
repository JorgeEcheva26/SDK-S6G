from evolved5g.sdk import CAPIFProviderConnector
import emulator_utils
def offboard_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=emulator_utils.get_config_file())

    capif_connector.offboard_and_deregister_nef()
    print("COMPLETADO")

    

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    offboard_capif_nef_connector()

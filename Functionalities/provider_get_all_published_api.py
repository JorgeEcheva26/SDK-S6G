import sys
sys.path.insert(0, '/Users/IDB0128/Documents/OpenCapif/SDK-S6G/Safe-6g/')


from sdk import CAPIFProviderConnector, ServiceDiscoverer
import emulator_utils
def showcase_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(config_file=emulator_utils.get_config_file())

    capif_connector.get_all_services()
    print("COMPLETED")

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    showcase_capif_nef_connector()

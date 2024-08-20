

from evolved5g.sdk import CAPIFInvokerConnector, ServiceDiscoverer
import emulator_utils

def showcase_capif_connector():
    """
        This method showcases how one can use the CAPIFConnector class.
        This class is intended for use within the evolved5G Command Line interface.
        It is a low level class part of the SDK that is not required to use while creating invokers
    """

    capif_connector = CAPIFInvokerConnector(config_file=emulator_utils.get_config_file())

    capif_connector.register_and_onboard_Invoker()
    print("COMPLETED")

if __name__ == "__main__":
    #Let's register invoker to CAPIF. This should happen exactly once
    showcase_capif_connector()




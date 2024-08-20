import sys
import os

# Agrega la ruta del archivo al sys.path
sys.path.append('/Users/IDB0128/Documents/OpenCapif/SDK-S6G')



from evolved5g.sdk import CAPIFInvokerConnector, ServiceDiscoverer
import emulator_utils

def showcase_offboard_and_deregister_invoker():
    capif_connector = CAPIFInvokerConnector(config_file=emulator_utils.get_config_file())
    capif_connector.offboard_and_deregister_Invoker()
    print("COMPLETED")


if __name__ == "__main__":
    showcase_offboard_and_deregister_invoker()



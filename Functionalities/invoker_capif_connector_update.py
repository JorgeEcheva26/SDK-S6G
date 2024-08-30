
import sys
sys.path.insert(0, '/Users/IDB0128/Documents/OpenCapif/SDK-S6G/Safe-6g/')

# Ahora importa las clases desde tu archivo sdk.py
from sdk import CAPIFInvokerConnector

import emulator_utils

def showcase_capif_connector():
    """
        This method showcases how one can use the CAPIFConnector class.
        This class is intended for use within the evolved5G Command Line interface.
        It is a low level class part of the SDK that is not required to use while creating invokers
    """

    capif_connector = CAPIFInvokerConnector(config_file=emulator_utils.get_config_file())

    capif_connector.update_Invoker()
    print("COMPLETED")

if __name__ == "__main__":
    #Let's register invoker to CAPIF. This should happen exactly once
    showcase_capif_connector()


""" # Importa el módulo completo para evitar problemas con rutas relativas
import sys
sys.path.insert(0, '/Users/IDB0128/Documents/OpenCapif/SDK-S6G/Safe-6g/')

# Ahora importa las clases desde tu archivo sdk.py
from sdk import CAPIFInvokerConnector, ServiceDiscoverer

"""

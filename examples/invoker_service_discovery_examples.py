from evolved5g.sdk import CAPIFInvokerConnector, ServiceDiscoverer

import emulator_utils



def showcase_access_token_retrieval_from_capif():
    service_discoverer = ServiceDiscoverer(config_file=emulator_utils.get_config_file())
    service_discoverer.discover()
    

if __name__ == "__main__":
    #The following code assumes that you have already registered the net app to capif.
    #showcase_service_discovery()
    #showcase_retrieve_endpoint_url_from_tsn()
    showcase_access_token_retrieval_from_capif()
    print("COMPLETED")

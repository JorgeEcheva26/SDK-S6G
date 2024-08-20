from evolved5g.sdk import CAPIFInvokerConnector, ServiceDiscoverer

import emulator_utils

def showcase_service_discovery():
    service_discoverer = ServiceDiscoverer(folder_path_for_certificates_and_api_key="/Users/IDB0128/Documents/OpenCapif/test_certificate_folder",
                                           capif_host="capifcore",
                                           capif_https_port=443
                                           )
    endpoints = service_discoverer.discover_service_apis()
    print(endpoints)

def showcase_retrieve_endpoint_url_from_tsn():
    service_discoverer = ServiceDiscoverer(folder_path_for_certificates_and_api_key="/Users/IDB0128/Documents/OpenCapif/test_certificate_folder",
                                           capif_host="capifcore",
                                           capif_https_port=443
                                           )
    print("The endpoint for api name: /tsn/api/ and resource: TSN_LIST_PROFILES")
    url = service_discoverer.retrieve_specific_resource_name(
        "/tsn/api/",
        "TSN_LIST_PROFILES"
    )
    print(url)

def showcase_retrieve_endpoint_url_from_nef():
    service_discoverer = ServiceDiscoverer(folder_path_for_certificates_and_api_key="/Users/IDB0128/Documents/OpenCapif/test_certificate_folder",
                                           capif_host="capifcore",
                                           capif_https_port=443
                                           )
    url = service_discoverer.retrieve_specific_resource_name(
        "/nef/api/v1/3gpp-monitoring-event/",
        "MONITORING_SUBSCRIPTIONS"
    )
    print("The endpoint for api name: /nef/api/v1/3gpp-monitoring-event/ and resource: MONITORING_SUBSCRIPTIONS")
    print(url)


def showcase_access_token_retrieval_from_capif():
    service_discoverer = ServiceDiscoverer(config_file=emulator_utils.get_config_file())
    service_discoverer.discover_and_get_access_tokens()
    

if __name__ == "__main__":
    #The following code assumes that you have already registered the net app to capif.
    #showcase_service_discovery()
    #showcase_retrieve_endpoint_url_from_tsn()
    showcase_access_token_retrieval_from_capif()
    print("COMPLETED")

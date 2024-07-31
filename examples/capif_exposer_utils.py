

def nef_exposer_get_certificate_folder() -> str:
    return "/Users/IDB0128/Documents/OpenCapif/test_nef_certificate_folder"

def nef_exposer_get_sample_api_description_path() -> str:
    return "/Users/IDB0128/Documents/OpenCapif/SDK-S6G/examples/capif_exposer_sample_files/nef_api_description_sample.json"

def nef_exposer_get_sample_api_description_path_that_is_stored_in_capif()->str:
    return "/Users/IDB0128/Documents/OpenCapif/test_certificate_folder/CAPIF_nef_api_description_sample.json"

def tsn_exposer_get_certificate_folder() -> str:
    return "/home/alex/Projects/test_tsn_certificate_folder"

def tsn_exposer_get_sample_api_description_path() -> str:
    return  "/Users/IDB0128/Documents/OpenCapif/SDK-S6G/examples/capif_exposer_sample_files/tsn_api_description_sample.json"


def get_demo_invoker_id()->str:
    """
    When you register a Net App to CAPIF it is assigner an api invoker id.
        You can find api invoker ids in the mongo database of CAPIF. http://localhost:8082/db/capif/invokerdetails
    If your CAPIF instance does not have any NetApps registered, you can run example "netapp_capif_connector_examples.py"

    :return: An api_invoker_id that exists in CAPIF database

    """

    return "33c2f9b99814ddfb7b3e8b671f0d58"

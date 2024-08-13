from evolved5g import swagger_client
from evolved5g.swagger_client import LoginApi, User
from evolved5g.swagger_client.models import Token


def get_token_for_nef_emulator() -> Token:

    username = "admin@my-email.com"
    password = "pass"
    # User name and pass matches are set in the .env of the docker of NEF_EMULATOR. See
    # https://github.com/EVOLVED-5G/NEF_emulator
    configuration = swagger_client.Configuration()
    # The host of the 5G API (emulator)
    configuration.host = get_url_of_the_nef_emulator()
    configuration.verify_ssl = False
    api_client = swagger_client.ApiClient(configuration=configuration)
    api_client.select_header_content_type(["application/x-www-form-urlencoded"])
    api = LoginApi(api_client)
    token = api.login_access_token_api_v1_login_access_token_post("", username, password, "", "", "")
    return token

def get_url_of_the_nef_emulator() -> str:
    return "https://localhost:4443"

def get_folder_path_for_netapp_certificates_and_capif_api_key()->str:
    """
    This is the folder that is provided when you registered the NetApp to CAPIF.
    It contains the certificates and the api.key needed to communicate with the CAPIF server.
    Make sure to change this path name to match your environment!
    :return:
    """
    return "/Users/IDB0128/Documents/OpenCapif/test_certificate_folder"

def get_capif_host()->str:
    """
    When running CAPIF via docker (by running ./run.sh) you should have at your /etc/hosts the following record
    127.0.0.1       capifcore
    :return:
    """
    return "capifcore"

def get_capif_https_port()->int:
    """
    This is the default https port when running CAPIF via docker
    :return:
    """
    return 443

def get_config_file()-> str : 
    return "/Users/IDB0128/Documents/OpenCapif/SDK-S6G/examples/Config_files/config.json"

def get_register_file()-> str : 
    return "/Users/IDB0128/Documents/OpenCapif/SDK-S6G/examples/Config_files/register.json"



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

def get_provider_config_file()->str:
    return "/Users/IDB0128/Documents/OpenCapif/SDK-S6G/examples/Config_files/Provider_config.json"

import os
import logging
from typing import List, Union, Optional
from requests.auth import HTTPBasicAuth
from evolved5g import swagger_client
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass
from evolved5g.swagger_client import (
    MonitoringEventAPIApi,
    MonitoringEventSubscriptionCreate,
    MonitoringEventSubscription,
    SessionWithQoSAPIApi,
    AsSessionWithQoSSubscriptionCreate,
    Snssai,
    UsageThreshold,
    AsSessionWithQoSSubscription,
    QosMonitoringInformation,
    RequestedQoSMonitoringParameters,
    ReportingFrequency,
    MonitoringEventReport,
    CellsApi,
    Cell,
)
import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ahora realiza tu solicitud HTTPS a 'localhost'

from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (
    dump_certificate_request,
    dump_privatekey,
    load_publickey,
    PKey,
    TYPE_RSA,
    X509Req,
    dump_publickey,
)
import requests
import json
from uuid import uuid4
import warnings
from requests.exceptions import RequestsDependencyWarning
warnings.filterwarnings("ignore", category=RequestsDependencyWarning)

# Configuración básica del logger
logging.basicConfig(
    level=logging.INFO,  # Nivel mínimo de severidad a registrar
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Formato del mensaje de log
    handlers=[
        logging.FileHandler("sdk_logs.log"),  # Registra en un archivo
        logging.StreamHandler()  # También muestra en la consola
    ]
)

class CAPIFInvokerConnector:
    """
    Τhis class is responsbile for onboarding an Invoker (ex. a Invoker) to CAPIF
    """
    def __init__(self,
                 config_file: str ):

        # Inicializar logger
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("Initializing CAPIFInvokerConnector")

        # Cargar configuración desde archivo si es necesario
        config = self.__load_config_file(config_file)

        
        

        # Asignar valores desde variables de entorno o desde el archivo de configuración
        self.folder_to_store_certificates = os.getenv('FOLDER_TO_STORE_CERTIFICATES', config.get('folder_to_store_certificates','')).strip()
        
        capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
        register_host = os.getenv('REGISTER_HOST', config.get('register_host', '')).strip()
        capif_http_port = str(os.getenv('CAPIF_HTTP_PORT', config.get('capif_http_port', '')).strip())
        capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
        capif_register_port = str(os.getenv('CAPIF_REGISTER_PORT', config.get('capif_register_port', '')).strip())
        capif_invoker_username = os.getenv('CAPIF_INVOKER_USERNAME', config.get('capif_invoker_username', '')).strip()
        capif_invoker_password = os.getenv('CAPIF_INVOKER_PASSWORD', config.get('capif_invoker_password', '')).strip()
        capif_register_username = os.getenv('CAPIF_REGISTER_USERNAME', config.get('capif_register_username', '')).strip()
        capif_register_password = os.getenv('CAPIF_REGISTER_PASSWORD', config.get('capif_register_password', '')).strip()
        capif_callback_url = os.getenv('CAPIF_CALLBACK_URL', config.get('capif_callback_url', '')).strip()
        description = os.getenv('DESCRIPTION', config.get('description', '')).strip()
        csr_common_name = os.getenv('CSR_COMMON_NAME', config.get('csr_common_name', '')).strip()
        csr_organizational_unit = os.getenv('CSR_ORGANIZATIONAL_UNIT', config.get('csr_organizational_unit', '')).strip()
        csr_organization = os.getenv('CSR_ORGANIZATION', config.get('csr_organization', '')).strip()
        crs_locality = os.getenv('CRS_LOCALITY', config.get('crs_locality', '')).strip()
        csr_state_or_province_name = os.getenv('CSR_STATE_OR_PROVINCE_NAME', config.get('csr_state_or_province_name', '')).strip()
        csr_country_name = os.getenv('CSR_COUNTRY_NAME', config.get('csr_country_name', '')).strip()
        csr_email_address = os.getenv('CSR_EMAIL_ADDRESS', config.get('csr_email_address', '')).strip()
        uuid = os.getenv('UUID', config.get('uuid', '')).strip()


        # Resto del código original para inicializar URLs y otros atributos
        if len(capif_http_port) == 0 or int(capif_http_port) == 80:
            self.capif_http_url = "http://" + capif_host.strip() + "/"
        else:
            self.capif_http_url = (
                "http://" + capif_host.strip() + ":" + capif_http_port.strip() + "/"
            )

        if len(capif_https_port) == 0 or int(capif_https_port) == 443:
            self.capif_https_url = "https://" + capif_host.strip() + "/"
        else:
            self.capif_https_url = (
                "https://" + capif_host.strip() + ":" + capif_https_port.strip() + "/"
            )

        if len(capif_register_port) == 0:
            self.capif_register_url = "https://" + register_host.strip() + ":8084/"
        else:
            self.capif_register_url = (
                "https://" + register_host.strip() + ":" + capif_register_port.strip() + "/"
            )

        self.capif_callback_url = self.__add_trailing_slash_to_url_if_missing(
            capif_callback_url.strip()
        )
        self.capif_register_username = capif_register_username
        self.capif_register_password = capif_register_password
        self.capif_invoker_username = capif_invoker_username
        self.capif_invoker_password = capif_invoker_password
        self.description = description
        self.csr_common_name = "invoker_" + csr_common_name
        self.csr_organizational_unit = csr_organizational_unit
        self.csr_organization = csr_organization
        self.crs_locality = crs_locality
        self.csr_state_or_province_name = csr_state_or_province_name
        self.csr_country_name = csr_country_name
        self.csr_email_address = csr_email_address
        self.capif_api_details_filename = "capif_api_security_context_details.json"
        self.capif_api_details = self.__load_invoker_api_details()
        self.uuid=uuid
        self.logger.info("CAPIFInvokerConnector initialized")

    def __load_config_file(self, config_file: str):
            """Carga el archivo de configuración."""
            try:
                with open(config_file, 'r') as file:
                    return json.load(file)
            except FileNotFoundError:
                self.logger.warning(f"Configuration file {config_file} not found. Using defaults or environment variables.")
                return {}

    def __add_trailing_slash_to_url_if_missing(self, url):
        if url[len(url) - 1] != "/":
            url = url + "/"
        return url

    def register_and_onboard_Invoker(self) -> None:
        self.logger.info("Registering and onboarding Invoker")
        try:
            public_key = self.__create_private_and_public_keys()
            capif_postauth_info = self.__save_capif_ca_root_file_and_get_auth_token()
            capif_onboarding_url = capif_postauth_info["ccf_onboarding_url"]
            capif_discover_url = capif_postauth_info["ccf_discover_url"]
            capif_access_token = capif_postauth_info["access_token"]
            api_invoker_id = self.__onboard_invoker_to_capif_and_create_the_signed_certificate(
                public_key, capif_onboarding_url, capif_access_token
            )
            self.__write_to_file(self.csr_common_name, api_invoker_id, capif_discover_url)
            self.logger.info("Invoker registered and onboarded successfully")
        except Exception as e:
            self.logger.error(f"Error during Invoker registration and onboarding: {e}")
            raise

    def __load_invoker_api_details(self):
        self.logger.debug("Loading Invoker API details")
        with open(
            self.folder_to_store_certificates + self.capif_api_details_filename, "r"
        ) as openfile:
            return json.load(openfile)

    def __offboard_Invoker(self) -> None:
        self.logger.info("Offboarding Invoker")
        try:
            capif_api_details = self.__load_invoker_api_details()
            url = (
                self.capif_https_url
                + "api-invoker-management/v1/onboardedInvokers/"
                + capif_api_details["api_invoker_id"]
            )

            signed_key_crt_path = (
                self.folder_to_store_certificates + capif_api_details["csr_common_name"] + ".crt"
            )
            private_key_path = self.folder_to_store_certificates + "private.key"

            response = requests.request(
                "DELETE",
                url,
                cert=(signed_key_crt_path, private_key_path),
                verify=self.folder_to_store_certificates + "ca.crt",
            )
            response.raise_for_status()
            self.logger.info("Invoker offboarded successfully")
        except Exception as e:
            self.logger.error(f"Error during Invoker offboarding: {e}")
            raise

    def offboard_and_deregister_Invoker(self) -> None:
        self.logger.info("Offboarding and deregistering Invoker")
        try:
            self.__offboard_Invoker()
            
            self.logger.info("Invoker offboarded and deregistered successfully")
        except Exception as e:
            self.logger.error(f"Error during Invoker offboarding and deregistering: {e}")
            raise

    def __create_private_and_public_keys(self) -> str:
        self.logger.info("Creating private and public keys")
        try:
            private_key_path = self.folder_to_store_certificates + "private.key"
            csr_file_path = self.folder_to_store_certificates + "cert_req.csr"

            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            req = X509Req()
            req.get_subject().CN = self.csr_common_name
            req.get_subject().O = self.csr_organization
            req.get_subject().OU = self.csr_organizational_unit
            req.get_subject().L = self.crs_locality
            req.get_subject().ST = self.csr_state_or_province_name
            req.get_subject().C = self.csr_country_name
            req.get_subject().emailAddress = self.csr_email_address
            req.set_pubkey(key)
            req.sign(key, "sha256")

            with open(csr_file_path, "wb+") as f:
                f.write(dump_certificate_request(FILETYPE_PEM, req))
                public_key = dump_certificate_request(FILETYPE_PEM, req)
            with open(private_key_path, "wb+") as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))

            self.logger.info("Keys created successfully")
            return public_key
        except Exception as e:
            self.logger.error(f"Error during key creation: {e}")
            raise

    
    

    def de_register_from_capif(self, admin_token):
        self.logger.info("Deregistering from CAPIF")
        try:
            url = self.capif_register_url + "deleteUser/" + self.capif_api_details["uuid"]

            headers = {
                "Authorization": "Bearer {}".format(admin_token),
                "Content-Type": "application/json",
            }
            response = requests.request(
                "DELETE", url, headers=headers, data=None, verify=False
            )
            response.raise_for_status()
            self.logger.info("Deregistered from CAPIF successfully")
        except Exception as e:
            self.logger.error(f"Error during deregistration from CAPIF: {e}")
            raise

    def __save_capif_ca_root_file_and_get_auth_token(self):
        self.logger.info("Saving CAPIF CA root file and getting auth token")
        try:
            url = self.capif_register_url + "getauth"

            response = requests.request(
                "GET",
                url,
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth(self.capif_invoker_username, self.capif_invoker_password),
                verify=False,
            )

            response.raise_for_status()
            response_payload = json.loads(response.text)
            ca_root_file = open(self.folder_to_store_certificates + "ca.crt", "wb+")
            ca_root_file.write(bytes(response_payload["ca_root"], "utf-8"))
            self.logger.info("CAPIF CA root file saved and auth token obtained successfully")
            return response_payload
        except Exception as e:
            self.logger.error(f"Error during saving CAPIF CA root file and getting auth token: {e}")
            raise

    def __cache_security_context(self):
        self.logger.info("Caching security context")
        try:
            with open(
                self.folder_to_store_certificates + "capif_api_security_context_details.json", "w"
            ) as outfile:
                json.dump(self.capif_api_details, outfile)
            self.logger.info("Security context cached successfully")
        except Exception as e:
            self.logger.error(f"Error during caching security context: {e}")
            raise

    def __onboard_invoker_to_capif_and_create_the_signed_certificate(
        self, public_key, capif_onboarding_url, capif_access_token
    ):
        self.logger.info("Onboarding Invoker to CAPIF and creating signed certificate")
        try:
            url = self.capif_https_url + capif_onboarding_url
            payload_dict = {
                "notificationDestination": self.capif_callback_url,
                "supportedFeatures": "fffffff",
                "apiInvokerInformation": self.csr_common_name,
                "websockNotifConfig": {
                    "requestWebsocketUri": True,
                    "websocketUri": "websocketUri",
                },
                "onboardingInformation": {"apiInvokerPublicKey": str(public_key, "utf-8")},
                "requestTestNotification": True,
            }
            payload = json.dumps(payload_dict)
            headers = {
                "Authorization": "Bearer {}".format(capif_access_token),
                "Content-Type": "application/json",
            }
            response = requests.request(
                "POST",
                url,
                headers=headers,
                data=payload,
                verify=self.folder_to_store_certificates + "ca.crt",
            )
            response.raise_for_status()
            response_payload = json.loads(response.text)
            certification_file = open(
                self.folder_to_store_certificates + self.csr_common_name + ".crt", "wb"
            )
            certification_file.write(
                bytes(
                    response_payload["onboardingInformation"]["apiInvokerCertificate"],
                    "utf-8",
                )
            )
            certification_file.close()
            self.logger.info("Invoker onboarded and signed certificate created successfully")
            return response_payload["apiInvokerId"]
        except Exception as e:
            self.logger.error(f"Error during onboarding Invoker to CAPIF: {e}")
            raise

    def __write_to_file(self, csr_common_name, api_invoker_id, discover_services_url):
        self.logger.info("Writing API invoker ID and service discovery URL to file")
        try:
            with open(
                self.folder_to_store_certificates + self.capif_api_details_filename, "w"
            ) as outfile:
                json.dump(
                    {
                        "csr_common_name": csr_common_name,
                        "api_invoker_id": api_invoker_id,
                        "discover_services_url": discover_services_url,
                        "uuid": self.uuid,
                    },
                    outfile,
                )
            self.logger.info("API invoker ID and service discovery URL written to file successfully")
        except Exception as e:
            self.logger.error(f"Error during writing to file: {e}")
            raise

class CAPIFProviderConnector:
    """
    Τhis class is responsible for onboarding an exposer (eg. NEF emulator) to CAPIF
    """

    def __init__(
            self,
            config_file: str
    ):
        """
        :param certificates_folder: The folder where certificates will be created and stored.
        :param description: A short description of the Provider
        :param capif_host:
        :param capif_http_port:
        :param capif_https_port:
        :param capif_provider_username: The CAPIF username of your provider
        :param capif_provider_password: The CAPIF password  of your provider
        :param csr_common_name: The CommonName that will be used in the generated X.509 certificate
        :param csr_organizational_unit:The OrganizationalUnit that will be used in the generated X.509 certificate
        :param csr_organization: The Organization that will be used in the generated X.509 certificate
        :param crs_locality: The Locality that will be used in the generated X.509 certificate
        :param csr_state_or_province_name: The StateOrProvinceName that will be used in the generated X.509 certificate
        :param csr_country_name: The CountryName that will be used in the generated X.509 certificate
        :param csr_email_address: The email that will be used in the generated X.509 certificate

        """
        # add the trailing slash if it is not already there using os.path.join
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("Initializing CAPIFIProviderConnector")

        config = self.__load_config_file(config_file)

        certificates_folder=os.getenv('CERTIFICATES_FOLDER', config.get('certificates_folder', '')).strip()
        capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
        capif_register_host = os.getenv('REGISTER_HOST', config.get('register_host', '')).strip()
        capif_http_port = str(os.getenv('CAPIF_HTTP_PORT', config.get('capif_http_port', '')).strip())
        capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
        capif_register_port = str(os.getenv('CAPIF_REGISTER_PORT', config.get('capif_register_port', '')).strip())
        capif_provider_username = os.getenv('CAPIF_PROVIDER_USERNAME', config.get('capif_provider_username', '')).strip()
        capif_provider_password = os.getenv('CAPIF_PROVIDER_PASSWORD', config.get('capif_provider_password', '')).strip()
        capif_register_username = os.getenv('CAPIF_REGISTER_USERNAME', config.get('capif_register_username', '')).strip()
        capif_register_password = os.getenv('CAPIF_REGISTER_PASSWORD', config.get('capif_register_password', '')).strip()
        description = os.getenv('DESCRIPTION', config.get('description', '')).strip()
        csr_common_name = os.getenv('CSR_COMMON_NAME', config.get('csr_common_name', '')).strip()
        csr_organizational_unit = os.getenv('CSR_ORGANIZATIONAL_UNIT', config.get('csr_organizational_unit', '')).strip()
        csr_organization = os.getenv('CSR_ORGANIZATION', config.get('csr_organization', '')).strip()
        crs_locality = os.getenv('CRS_LOCALITY', config.get('crs_locality', '')).strip()
        csr_state_or_province_name = os.getenv('CSR_STATE_OR_PROVINCE_NAME', config.get('csr_state_or_province_name', '')).strip()
        csr_country_name = os.getenv('CSR_COUNTRY_NAME', config.get('csr_country_name', '')).strip()
        csr_email_address = os.getenv('CSR_EMAIL_ADDRESS', config.get('csr_email_address', '')).strip()
        uuid=os.getenv('UUID', config.get('uuid', '')).strip()

        
        self.certificates_folder = os.path.join(certificates_folder.strip(), "")
        self.description = description
        self.csr_common_name = capif_provider_username
        # make sure the parameters are str
        capif_http_port = str(capif_http_port)
        self.capif_https_port = str(capif_https_port)
        
        if len(capif_http_port) == 0 or int(capif_http_port) == 80:
            self.capif_http_url = "http://" + capif_host.strip() + "/"
        else:
            self.capif_http_url = (
                    "http://" + capif_host.strip() + ":" + capif_http_port.strip() + "/"
            )

        if len(self.capif_https_port ) == 0 or int(self.capif_https_port ) == 443:
            self.capif_https_url = "https://" + capif_host.strip() + "/"
        else:
            self.capif_https_url = (
                    "https://" + capif_host.strip() + ":" + self.capif_https_port .strip() + "/"
            )

        if len(capif_register_port) == 0 :
            self.capif_register_url = "https://" + capif_register_host.strip() + ":8084/"
        else:
            self.capif_register_url = "https://" + capif_register_host.strip() + ":" + capif_register_port.strip() + "/"    


        self.capif_host = capif_host.strip()
        self.capif_provider_username = capif_provider_username
        self.capif_provider_password = capif_provider_password

        self.capif_register_host=capif_register_host
        self.capif_register_port=capif_register_port
        self.capif_register_username=capif_register_username
        self.capif_register_password=capif_register_password

        self.csr_common_name = csr_common_name
        self.csr_organizational_unit = csr_organizational_unit
        self.csr_organization = csr_organization
        self.crs_locality = crs_locality
        self.csr_state_or_province_name = csr_state_or_province_name
        self.csr_country_name = csr_country_name
        self.csr_email_address = csr_email_address
        self.uuid=uuid

    def __store_certificate(self) -> None:
        """
        Retrieves and stores the cert_server.pem from CAPIF
        """
        print("Retrieve capif_cert_server.pem , process may take a few minutes")
        cmd = "openssl s_client -connect {0}:{1}  | openssl x509 -text > {2}/capif_cert_server.pem".format(
            self.capif_host,
            self.capif_https_port,
            self.certificates_folder
        )
        os.system(cmd)
        print("cert_server.pem succesfully generated!")

    def __load_config_file(self, config_file: str):
            """Carga el archivo de configuración."""
            try:
                with open(config_file, 'r') as file:
                    return json.load(file)
            except FileNotFoundError:
                self.logger.warning(f"Configuration file {config_file} not found. Using defaults or environment variables.")
                return {}


    def __create_private_and_public_keys(self, api_prov_func_role) -> bytes:
        """
        Creates 2 keys in folder folder_to_store_certificates. An api_prov_func_role_private.key and a api_prov_func_role_private.public.csr key"
        :return: The contents of the public key
        """
        private_key_path = (
                self.certificates_folder + api_prov_func_role + "_private_key.key"
        )
        csr_file_path = self.certificates_folder + api_prov_func_role + "_public.csr"

        # create public/private key
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        # Generate CSR
        req = X509Req()

        # The role should always be put in the certificate .lower() by convention
        req.get_subject().CN = api_prov_func_role.lower()
        req.get_subject().O = self.csr_organization
        req.get_subject().OU = self.csr_organizational_unit
        req.get_subject().L = self.crs_locality
        req.get_subject().ST = self.csr_state_or_province_name
        req.get_subject().C = self.csr_country_name
        req.get_subject().emailAddress = self.csr_email_address
        req.set_pubkey(key)
        req.sign(key, "sha256")

        with open(csr_file_path, "wb+") as f:
            f.write(dump_certificate_request(FILETYPE_PEM, req))
            public_key = dump_certificate_request(FILETYPE_PEM, req)
        with open(private_key_path, "wb+") as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))

        return public_key

    def __onboard_exposer_to_capif(self, access_token, capif_onboarding_url):
        self.logger.info("Onboarding Provider to CAPIF")
        url = self.capif_https_url + capif_onboarding_url
        payload = {
            "apiProvFuncs": [
                {
                    "regInfo": {"apiProvPubKey": ""},
                    "apiProvFuncRole": "AEF",
                    "apiProvFuncInfo": "dummy_aef",
                },
                {
                    "regInfo": {"apiProvPubKey": ""},
                    "apiProvFuncRole": "APF",
                    "apiProvFuncInfo": "dummy_apf",
                },
                {
                    "regInfo": {"apiProvPubKey": ""},
                    "apiProvFuncRole": "AMF",
                    "apiProvFuncInfo": "dummy_amf",
                },
            ],
            "apiProvDomInfo": "This is provider",
            "suppFeat": "fff",
            "failReason": "string",
            "regSec": access_token,
        }
        for api_func in payload["apiProvFuncs"]:
            public_key = self.__create_private_and_public_keys(
                api_func["apiProvFuncRole"]
            )
            api_func["regInfo"]["apiProvPubKey"] = public_key.decode("utf-8")

        headers = {
            "Authorization": "Bearer {}".format(access_token),
            "Content-Type": "application/json",
        }

        response = requests.request(
            "POST",
            url,
            headers=headers,
            data=json.dumps(payload),
            verify=self.certificates_folder + "ca.crt",
        )
        
        response.raise_for_status()
        self.logger.info("Onboarding completed")
        response_payload = json.loads(response.text)
        return response_payload
   
    
    def __write_to_file(self, onboarding_response, capif_registration_id, publish_url):
        self.logger.info("Saving the most relevant onboarding data")
        for func_provile in onboarding_response["apiProvFuncs"]:
            with open(
                    self.certificates_folder
                    + "dummy_"
                    + func_provile["apiProvFuncRole"].lower()
                    + ".crt",
                    "wb",
            ) as certification_file:
                certification_file.write(
                    bytes(func_provile["regInfo"]["apiProvCert"], "utf-8")
                )

        with open(
                self.certificates_folder + "capif_provider_details.json", "w"
        ) as outfile:
            data = {
                "capif_registration_id": capif_registration_id,
                "uuid":self.uuid,
                "publish_url": publish_url,
            }
            for api_prov_func in onboarding_response["apiProvFuncs"]:
                key = api_prov_func["apiProvFuncRole"] + "_api_prov_func_id"
                value = api_prov_func["apiProvFuncId"]
                data[key] = value

            json.dump(data, outfile)
        self.logger.info("Data saved")

    
 
    def __save_capif_ca_root_file_and_get_auth_token(self):

        url = self.capif_register_url + "getauth"

        self.logger.info("Acquiring authorization by CAPIF")
        

        response = requests.request(
            "GET",
            url,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(self.capif_provider_username, self.capif_provider_password),
            verify=False
        )
        
        response.raise_for_status()
        self.logger.info("Authorization acquired")
        response_payload = json.loads(response.text)
        ca_root_file = open(self.certificates_folder + "ca.crt", "wb+")
        self.logger.info("Saving authority certification")
        ca_root_file.write(bytes(response_payload["ca_root"], "utf-8"))
        return response_payload

    
    def register_and_onboard_provider(self) -> None:
        
        # retrieve store the .pem certificate from CAPIF
        
        self.__store_certificate()
        capif_postauth_info = self.__save_capif_ca_root_file_and_get_auth_token()
        capif_onboarding_url = capif_postauth_info["ccf_api_onboarding_url"]
        access_token = capif_postauth_info["access_token"]
        ccf_publish_url=capif_postauth_info["ccf_publish_url"]
        

        onboarding_response = self.__onboard_exposer_to_capif(
            access_token, capif_onboarding_url
        )
        capif_registration_id=onboarding_response["apiProvDomId"]
        self.__write_to_file(
            onboarding_response, capif_registration_id, ccf_publish_url
        )



    def publish_services(self, service_api_description_json_full_path) -> dict:
        """
            :param service_api_description_json_full_path: The full path fo the service_api_description.json that contains
            the endpoints that will be published
            :return: The published services dictionary that was saved in CAPIF

        """

        with open(
                self.certificates_folder + "capif_provider_details.json", "r"
        ) as openfile:
            file = json.load(openfile)
            publish_url = file["publish_url"]
            AEF_api_prov_func_id = file["AEF_api_prov_func_id"]
            APF_api_prov_func_id = file["APF_api_prov_func_id"]
            print(AEF_api_prov_func_id)
            print(APF_api_prov_func_id)

        url = self.capif_https_url + publish_url.replace(
            "<apfId>", APF_api_prov_func_id
        )

        with open(service_api_description_json_full_path, "rb") as service_file:
            data = json.load(service_file)
            for profile in data["aefProfiles"]:
                profile["aefId"] = AEF_api_prov_func_id

        response = requests.request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(data),
            cert=(
                self.certificates_folder + "dummy_apf.crt",
                self.certificates_folder + "APF_private_key.key",
            ),
            verify=self.certificates_folder + "ca.crt",
        )
        
        response.raise_for_status()
        capif_response = response.text

        file_name = os.path.basename(service_api_description_json_full_path)
        with open(self.certificates_folder + "CAPIF_" + file_name, "w") as outfile:
            outfile.write(capif_response)

        return json.loads(capif_response)

    def offboard_and_deregister_nef(self):
        
        self.offboard_nef()
        
        
        


    
    
    def offboard_nef(self) ->None:
        self.logger.info("Offboarding the provider")
        capif_api_details = self.__load_nef_api_details()
        url = self.capif_https_url+ "api-provider-management/v1/registrations/" +capif_api_details["capif_registration_id"]

        signed_key_crt_path = self.certificates_folder + "dummy_amf.crt"
        private_key_path = self.certificates_folder + "AMF_private_key.key"
        
        response = requests.request(
            "DELETE",
            url,
            cert=(signed_key_crt_path, private_key_path),
            verify=self.certificates_folder + "ca.crt"
        )
        response.raise_for_status()
        self.logger.info("Offboarding performed")

    def __load_nef_api_details(self):
        with open(
                    self.certificates_folder + "capif_provider_details.json",
                    "r",
            ) as openfile:
                return json.load(openfile)

    
    
 
class ServiceDiscoverer:
    class ServiceDiscovererException(Exception):
        pass

    def __init__(
            self,
            config_file
    ):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("Initializing ServiceDiscoverer")

        config = self.__load_config_file(config_file)

        capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
        capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
        folder_path_for_certificates_and_api_key = str(os.getenv('FOLDER_PATH_FOR_CERTIFICATES_AND_API_KEY', config.get('folder_path_for_certificates_and_api_key', '')).strip())
        
        self.capif_host = capif_host
        self.capif_https_port = capif_https_port
        self.folder_to_store_certificates_and_api_key = os.path.join(
            folder_path_for_certificates_and_api_key.strip(), ""
        )
        self.capif_api_details = self.__load_provider_api_details()
        self.signed_key_crt_path = (
                self.folder_to_store_certificates_and_api_key
                + self.capif_api_details["csr_common_name"] + ".crt"
        )
        self.private_key_path = self.folder_to_store_certificates_and_api_key + "private.key"
        self.ca_root_path = self.folder_to_store_certificates_and_api_key + "ca.crt"
        self.logger.info("ServiceDiscoverer initialized correctly")

    def get_api_provider_id(self):
        return self.capif_api_details["api_provider_id"]
    
    def __load_config_file(self, config_file: str):
            """Carga el archivo de configuración."""
            try:
                with open(config_file, 'r') as file:
                    return json.load(file)
            except FileNotFoundError:
                self.logger.warning(f"Configuration file {config_file} not found. Using defaults or environment variables.")
                return {}


    def __load_provider_api_details(self):
        try:
            with open(
                    self.folder_to_store_certificates_and_api_key + "capif_api_security_context_details.json",
                    "r",
            ) as openfile:
                details = json.load(openfile)
            self.logger.info("Api invoker details correctly loaded")
            return details
        except Exception as e:
            self.logger.error("Error while loading Api invoker details: %s", str(e))
            raise

    def _add_trailing_slash_to_url_if_missing(self, url):
        if not url.endswith("/"):
            url += "/"
        return url

    def get_access_token(self, api_name, api_id, aef_id):
        """
        :param api_name: El nombre del API devuelto por descubrir servicios
        :param api_id: El id del API devuelto por descubrir servicios
        :param aef_id: El aef_id relevante devuelto por descubrir servicios
        :return: El token de acceso (jwt)
        """
        self.logger.info("Getting access token for api_name=%s, api_id=%s, aef_id=%s", api_name, api_id, aef_id)

        if self.__security_context_does_not_exist():
            self.logger.info("There is no security context. Registering a new security service.")
            self.capif_api_details["registered_security_contexes"] = []
            self.capif_api_details["registered_security_contexes"].append({"api_id": api_id, "aef_id": aef_id})
            self.__register_security_service(api_id, aef_id)
            self.__cache_security_context()
        elif self.__security_context_for_given_api_id_and_aef_id_does_not_exist(api_id, aef_id):
            self.logger.info("The security context for api_id=%s and aef_id=%s does not exist. Updating the security service.", api_id, aef_id)
            self.capif_api_details["registered_security_contexes"].append({"api_id": api_id, "aef_id": aef_id})
            self.__update_security_service(api_id, aef_id)
            self.__cache_security_context()

        token_dic = self.__get_security_token(api_name, aef_id)
        self.logger.info("Access token successfully obtained")
        return token_dic["access_token"]

    def __security_context_does_not_exist(self):
        return "registered_security_contexes" not in self.capif_api_details

    def __security_context_for_given_api_id_and_aef_id_does_not_exist(self, api_id, aef_id):
        contexes = self.capif_api_details.get("registered_security_contexes", [])
        results = [c for c in contexes if c['api_id'] == api_id and c["aef_id"] == aef_id]
        return len(results) == 0

    def __cache_security_context(self):
        try:
            with open(
                    self.folder_to_store_certificates_and_api_key + "capif_api_security_context_details.json", "w"
            ) as outfile:
                json.dump(self.capif_api_details, outfile)
            self.logger.info("Security context saved correctly")
        except Exception as e:
            self.logger.error("Error when saving the security context: %s", str(e))
            raise

    def __update_security_service(self, api_id, aef_id):
        """
        :param api_id: El id del API devuelto por descubrir servicios
        :param aef_id: El aef_id devuelto por descubrir servicios
        :return: None
        """
        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/trustedInvokers/{self.capif_api_details['api_invoker_id']}/update"
        payload = {
            "securityInfo": [],
            "notificationDestination": "https://mynotificationdest.com",
            "requestTestNotification": True,
            "websockNotifConfig": {
                "websocketUri": "string",
                "requestWebsocketUri": True
            },
            "supportedFeatures": "fff"
        }

        for security_info in self.capif_api_details.get("registered_security_contexes", []):
            payload["securityInfo"].append({
                "prefSecurityMethods": ["OAUTH"],
                "aefId": security_info["aef_id"],
                "apiId": security_info["api_id"]
            })

        try:
            response = requests.post(url,
                                    json=payload,
                                    cert=(self.signed_key_crt_path, self.private_key_path),
                                    verify=self.ca_root_path
                                    )
            response.raise_for_status()
            self.logger.info("Servicio de seguridad actualizado correctamente")
        except requests.RequestException as e:
            self.logger.error("Error al actualizar el servicio de seguridad: %s", str(e))
            raise

    def __register_security_service(self, api_id, aef_id):
        """
        :param api_id: El id del API devuelto por descubrir servicios
        :param aef_id: El aef_id devuelto por descubrir servicios
        :return: None
        """
        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/trustedInvokers/{self.capif_api_details['api_invoker_id']}"
        payload = {
            "securityInfo": [
                {
                    "prefSecurityMethods": ["Oauth"],
                    "authenticationInfo": "string",
                    "authorizationInfo": "string"
                }
            ],
            "notificationDestination": "https://mynotificationdest.com",
            "requestTestNotification": True,
            "websockNotifConfig": {
                "websocketUri": "string",
                "requestWebsocketUri": True
            },
            "supportedFeatures": "fff"
        }

        for profile in payload["securityInfo"]:
            profile["aefId"] = aef_id
            profile["apiId"] = api_id

        try:
            response = requests.put(url,
                                    json=payload,
                                    cert=(self.signed_key_crt_path, self.private_key_path),
                                    verify=self.ca_root_path
                                    )
            response.raise_for_status()
            self.logger.info("Security service properly registered")
        except requests.RequestException as e:
            self.logger.error("Error when registering the security service: %s", str(e))
            raise

    def __get_security_token(self, api_name, aef_id):
        """
        :param api_name: El nombre del API devuelto por descubrir servicios
        :param aef_id: El aef_id relevante devuelto por descubrir servicios
        :return: El token de acceso (jwt)
        """
        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/securities/{self.capif_api_details['api_invoker_id']}/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.capif_api_details["api_invoker_id"],
            "client_secret": "string",
            "scope": f"3gpp#{aef_id}:{api_name}"
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        try:
            response = requests.post(url,
                                     headers=headers,
                                     data=payload,
                                     cert=(self.signed_key_crt_path, self.private_key_path),
                                     verify=self.ca_root_path
                                     )
            response.raise_for_status()
            response_payload = response.json()
            self.logger.info("Security token successfully obtained")
            return response_payload
        except requests.RequestException as e:
            self.logger.error("Error obtaining the security token: %s", str(e))
            raise

    def discover_service_apis(self):
        """
        Descubre los APIs de servicio desde CAPIF.
        :return: Payload JSON con los detalles de los APIs de servicio
        """
        url = f"https://{self.capif_host}:{self.capif_https_port}/{self.capif_api_details['discover_services_url']}{self.capif_api_details['api_invoker_id']}"
        try:
            response = requests.get(
                url,
                headers={"Content-Type": "application/json"},
                cert=(self.signed_key_crt_path, self.private_key_path),
                verify=self.ca_root_path
            )
            response.raise_for_status()
            response_payload = response.json()
            self.logger.info("Service APIs successfully discovered")
            return response_payload
        except requests.RequestException as e:
            self.logger.error("Error discovering service APIs: %s", str(e))
            raise

    def retrieve_api_description_by_name(self, api_name):
        """
        Recupera la descripción del API por nombre.
        :param api_name: Nombre del API
        :return: Descripción del API
        """
        self.logger.info("Retrieving the API description for api_name=%s", api_name)
        capif_apifs = self.discover_service_apis()
        endpoints = [api for api in capif_apifs["serviceAPIDescriptions"] if api["apiName"] == api_name]
        if not endpoints:
            error_message = (
                f"Could not find available endpoints for api_name: {api_name}. "
                "Make sure that a) your Invoker is registered and onboarded to CAPIF and "
                "b) the NEF emulator has been registered and onboarded to CAPIF"
            )
            self.logger.error(error_message)
            raise ServiceDiscoverer.ServiceDiscovererException(error_message)
        else:
            self.logger.info("API description successfully retrieved")
            return endpoints[0]

    def retrieve_specific_resource_name(self, api_name, resource_name):
        """
        Recupera la URL para recursos específicos dentro de los APIs.
        :param api_name: Nombre del API
        :param resource_name: Nombre del recurso
        :return: URL del recurso específico
        """
        self.logger.info("Retrieving the URL for resource_name=%s in api_name=%s", resource_name, api_name)
        api_description = self.retrieve_api_description_by_name(api_name)
        version_dictionary = api_description["aefProfiles"][0]["versions"][0]
        version = version_dictionary["apiVersion"]
        resources = version_dictionary["resources"]
        uris = [resource["uri"] for resource in resources if resource["resourceName"] == resource_name]

        if not uris:
            error_message = f"Could not find resource_name: {resource_name} at api_name {api_name}"
            self.logger.error(error_message)
            raise ServiceDiscoverer.ServiceDiscovererException(error_message)
        else:
            uri = uris[0]
            if not uri.startswith("/"):
                uri = "/" + uri
            if api_name.endswith("/"):
                api_name = api_name[:-1]
            result_url = api_name + "/" + version + uri
            self.logger.info("URL of the specific resource successfully retrieved: %s", result_url)
            return result_url



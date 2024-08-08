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
    Τhis class is responsbile for onboarding an Invoker (ex. a NetApp) to CAPIF
    """
    def __init__(self, 
                 folder_to_store_certificates: str, 
                 capif_host: str, 
                 register_host: str, 
                 capif_http_port: str, 
                 capif_https_port: str, 
                 capif_register_port: str, 
                 capif_netapp_username: str, 
                 capif_netapp_password: str, 
                 capif_register_username: str, 
                 capif_register_password: str, 
                 capif_callback_url: str, 
                 description: str, 
                 csr_common_name: str, 
                 csr_organizational_unit: str, 
                 csr_organization: str, 
                 crs_locality: str, 
                 csr_state_or_province_name, 
                 csr_country_name, 
                 csr_email_address):

        # Inicializar logger
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("Initializing CAPIFInvokerConnector")

        # Resto del código original
        self.folder_to_store_certificates = os.path.join(
            folder_to_store_certificates.strip(), ""
        )
        capif_http_port = str(capif_http_port)
        capif_https_port = str(capif_https_port)
        capif_register_port = str(capif_register_port)
        register_host = str(register_host)
        
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
        self.capif_register_username = str(capif_register_username)
        self.capif_register_password = str(capif_register_password)
        self.capif_netapp_username = capif_netapp_username
        self.capif_netapp_password = capif_netapp_password
        self.description = description
        self.csr_common_name = "invoker_" + csr_common_name
        self.csr_organizational_unit = csr_organizational_unit
        self.csr_organization = csr_organization
        self.crs_locality = crs_locality
        self.csr_state_or_province_name = csr_state_or_province_name
        self.csr_country_name = csr_country_name
        self.csr_email_address = csr_email_address
        self.capif_api_details_filename = "capif_api_security_context_details.json"
        self.capif_api_details = self.__load_netapp_api_details()
        self.logger.info("CAPIFInvokerConnector initialized")

    def __add_trailing_slash_to_url_if_missing(self, url):
        if url[len(url) - 1] != "/":
            url = url + "/"
        return url

    def register_and_onboard_netapp(self) -> None:
        self.logger.info("Registering and onboarding NetApp")
        try:
            public_key = self.__create_private_and_public_keys()
            log_result = self.__log_to_capif()
            admintoken = log_result["access_token"]
            postcreation = self.__create_user(admintoken)
            self.uuid = postcreation["uuid"]
            capif_postauth_info = self.__save_capif_ca_root_file_and_get_auth_token()
            capif_onboarding_url = capif_postauth_info["ccf_onboarding_url"]
            capif_discover_url = capif_postauth_info["ccf_discover_url"]
            capif_access_token = capif_postauth_info["access_token"]
            api_invoker_id = self.__onboard_netapp_to_capif_and_create_the_signed_certificate(
                public_key, capif_onboarding_url, capif_access_token
            )
            self.__write_to_file(self.csr_common_name, api_invoker_id, capif_discover_url)
            self.logger.info("NetApp registered and onboarded successfully")
        except Exception as e:
            self.logger.error(f"Error during NetApp registration and onboarding: {e}")
            raise

    def __load_netapp_api_details(self):
        self.logger.debug("Loading NetApp API details")
        with open(
            self.folder_to_store_certificates + self.capif_api_details_filename, "r"
        ) as openfile:
            return json.load(openfile)

    def offboard_netapp(self) -> None:
        self.logger.info("Offboarding NetApp")
        try:
            capif_api_details = self.__load_netapp_api_details()
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
            self.logger.info("NetApp offboarded successfully")
        except Exception as e:
            self.logger.error(f"Error during NetApp offboarding: {e}")
            raise

    def offboard_and_deregister_netapp(self) -> None:
        self.logger.info("Offboarding and deregistering NetApp")
        try:
            self.offboard_netapp()
            log_result = self.__log_to_capif()
            admintoken = log_result["access_token"]
            self.de_register_from_capif(admintoken)
            self.logger.info("NetApp offboarded and deregistered successfully")
        except Exception as e:
            self.logger.error(f"Error during NetApp offboarding and deregistering: {e}")
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

    def __log_to_capif(self):
        self.logger.info("Logging in to CAPIF")
        try:
            url = self.capif_register_url + "login"

            response = requests.request(
                "POST",
                url,
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth(self.capif_register_username, self.capif_register_password),
                verify=False,
            )
            response.raise_for_status()
            response_payload = json.loads(response.text)
            self.logger.info("Logged in to CAPIF successfully")
            return response_payload
        except Exception as e:
            self.logger.error(f"Error during login to CAPIF: {e}")
            raise

    def __create_user(self, admin_token):
        self.logger.info("Creating user in CAPIF")
        try:
            url = self.capif_register_url + "createUser"
            payload = {
                "username": self.capif_netapp_username,
                "password": self.capif_netapp_password,
                "description": self.description,
                "email": self.csr_email_address,
                "enterprise": self.csr_organization,
                "country": self.crs_locality,
                "purpose": "SDK for SAFE 6G",
            }
            headers = {
                "Authorization": "Bearer {}".format(admin_token),
                "Content-Type": "application/json",
            }

            response = requests.request(
                "POST", url, headers=headers, data=json.dumps(payload), verify=False
            )
            response.raise_for_status()
            response_payload = json.loads(response.text)
            self.logger.info("User created successfully")
            return response_payload
        except Exception as e:
            self.logger.error(f"Error during user creation in CAPIF: {e}")
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
                auth=HTTPBasicAuth(self.capif_netapp_username, self.capif_netapp_password),
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

    def __onboard_netapp_to_capif_and_create_the_signed_certificate(
        self, public_key, capif_onboarding_url, capif_access_token
    ):
        self.logger.info("Onboarding NetApp to CAPIF and creating signed certificate")
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
            self.logger.info("NetApp onboarded and signed certificate created successfully")
            return response_payload["apiInvokerId"]
        except Exception as e:
            self.logger.error(f"Error during onboarding NetApp to CAPIF: {e}")
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
            certificates_folder: str,
            description: str,
            capif_host: str,
            capif_http_port: str,
            capif_https_port: str,
            capif_netapp_username,
            capif_netapp_password: str,
            csr_common_name: str,
            csr_organizational_unit: str,
            csr_organization: str,
            crs_locality: str,
            csr_state_or_province_name,
            csr_country_name,
            csr_email_address,
            capif_register_host:str,
            capif_register_port:str,
            capif_register_username:str,
            capif_register_password:str
    ):
        """
        :param certificates_folder: The folder where certificates will be created and stored.
        :param description: A short description of the Provider
        :param capif_host:
        :param capif_http_port:
        :param capif_https_port:
        :param capif_netapp_username: The CAPIF username of your netapp
        :param capif_netapp_password: The CAPIF password  of your netapp
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

        
        self.certificates_folder = os.path.join(certificates_folder.strip(), "")
        self.description = description
        self.csr_common_name = capif_netapp_username
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
        self.capif_netapp_username = capif_netapp_username
        self.capif_netapp_password = capif_netapp_password

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

    def __store_certificate_authority_file(self):
        url = self.capif_http_url + "ca-root"
        response = requests.request(
            "GET", url, headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        response_payload = json.loads(response.text)
        with open(self.certificates_folder + "ca.crt", "wb+") as ca_root:
            ca_root.write(bytes(response_payload["certificate"], "utf-8"))

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
        self.logger.info("Realizando el onboarding")
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
        self.logger.info("Onboarding completado")
        response_payload = json.loads(response.text)
        return response_payload

    def __register_to_capif(self):
        self.logger.info("Loggeandose en CAPIF")
        url = self.capif_register_url + "login"
        
        response = requests.request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(self.capif_register_username, self.capif_register_password),
            verify=False
        )
        response.raise_for_status()
        self.logger.info("Loggeo completado")

        response_payload = json.loads(response.text)
        return response_payload
 
    def __perform_authorization(self) -> str:
        """
        :return: the access_token from CAPIF
        """

        url = self.capif_http_url + "getauth"

        payload = dict()
        payload["username"] = self.capif_netapp_username
        payload["password"] = self.capif_netapp_password

        response = requests.request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
        )
        response.raise_for_status()
        response_payload = json.loads(response.text)

        return response_payload["access_token"]

    def __write_to_file(self, onboarding_response, capif_registration_id, publish_url,uuid):
        self.logger.info("Guardando los datos más relevantes del onboarding")
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
                "uuid":uuid,
                "publish_url": publish_url,
            }
            for api_prov_func in onboarding_response["apiProvFuncs"]:
                key = api_prov_func["apiProvFuncRole"] + "_api_prov_func_id"
                value = api_prov_func["apiProvFuncId"]
                data[key] = value

            json.dump(data, outfile)
        self.logger.info("Datos guardados")

    def __create_user(self,admin_token):


        self.logger.info("Creando usuario de CAPIF")
        url=self.capif_register_url + "createUser" 
        payload = dict()
        payload["username"] = self.capif_netapp_username
        payload["password"] = self.capif_netapp_password
        payload["description"]=self.description
        payload["email"]=self.csr_email_address
        payload["enterprise"]=self.csr_organization
        payload["country"]=self.crs_locality
        payload["purpose"]="SDK for SAFE 6G"
        headers = {
            "Authorization": "Bearer {}".format(admin_token),
            "Content-Type": "application/json",
        }
        
        response = requests.request(
            "POST",
            url,
            headers=headers,
            data=json.dumps(payload),
            verify=False
        )
        response.raise_for_status()
        self.logger.info("Usuario creado correctamente")
        response_payload = json.loads(response.text)
        return response_payload
 
    def __save_capif_ca_root_file_and_get_auth_token(self):

        url = self.capif_register_url + "getauth"

        self.logger.info("Obteniendo autorización de CAPIF")
        

        response = requests.request(
            "GET",
            url,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(self.capif_netapp_username, self.capif_netapp_password),
            verify=False
        )
        
        response.raise_for_status()
        self.logger.info("Autorización recibida")
        response_payload = json.loads(response.text)
        ca_root_file = open(self.certificates_folder + "ca.crt", "wb+")
        self.logger.info("Guardando certificado de autoridad")
        ca_root_file.write(bytes(response_payload["ca_root"], "utf-8"))
        return response_payload

    
    def register_and_onboard_provider(self) -> None:
        
        # retrieve store the .pem certificate from CAPIF
        
        self.__store_certificate()
        # register provider to CAPIF
        registration_result = self.__register_to_capif()
        admintoken =registration_result["access_token"]
        response=self.__create_user(admintoken)
        uuid=response["uuid"]
        capif_postauth_info = self.__save_capif_ca_root_file_and_get_auth_token()
        capif_onboarding_url = capif_postauth_info["ccf_api_onboarding_url"]
        access_token = capif_postauth_info["access_token"]
        ccf_publish_url=capif_postauth_info["ccf_publish_url"]
        #capif_registration_id = registration_result["id"]
        #ccf_publish_url = registration_result["ccf_publish_url"]
        #capif_onboarding_url = registration_result["ccf_api_onboarding_url"]

        onboarding_response = self.__onboard_exposer_to_capif(
            access_token, capif_onboarding_url
        )
        capif_registration_id=onboarding_response["apiProvDomId"]
        self.__write_to_file(
            onboarding_response, capif_registration_id, ccf_publish_url,uuid
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
        log_result = self.__log_to_capif()
        admintoken =log_result["access_token"]
        self.de_register_from_capif(admintoken)


    def __log_to_capif(self):

        url = self.capif_register_url + "login"
        
        response = requests.request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(self.capif_register_username, self.capif_register_password),
            verify=False
        )
        response.raise_for_status()
        response_payload = json.loads(response.text)
        return response_payload
    
    def offboard_nef(self) ->None:
        self.logger.info("Realizando el offboarding del provider")
        capif_api_details = self.__load_nef_api_details()
        url = self.capif_https_url+ "api-provider-management/v1/registrations/" +capif_api_details["capif_registration_id"]

        signed_key_crt_path = self.certificates_folder + "dummy_amf.crt"
        private_key_path = self.certificates_folder + "AMF_private_key.key"
        print(self.certificates_folder + "ca.crt")
        response = requests.request(
            "DELETE",
            url,
            cert=(signed_key_crt_path, private_key_path),
            verify=self.certificates_folder + "ca.crt"
        )
        response.raise_for_status()
        self.logger.info("Offboarding realizado")

    def __load_nef_api_details(self):
        with open(
                    self.certificates_folder + "capif_provider_details.json",
                    "r",
            ) as openfile:
                return json.load(openfile)

    def de_register_from_capif(self,admin_token):
        self.logger.info("Eliminando usuario de CAPIF")
        capif_api_details=self.__load_nef_api_details()

        url = self.capif_register_url + "deleteUser/" + capif_api_details["uuid"]
        
        headers = {
            "Authorization": "Bearer {}".format(admin_token),
            "Content-Type": "application/json",
        }
        response = requests.request(
            "DELETE",
            url,
            headers=headers,
            data=None,
            verify=False
        )
        response.raise_for_status()
        self.logger.info("Usuario eliminado")
 
class ServiceDiscoverer:
    class ServiceDiscovererException(Exception):
        pass

    def __init__(
            self,
            folder_path_for_certificates_and_api_key: str,
            capif_host: str,
            capif_https_port: int,
    ):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info("Inicializando ServiceDiscoverer")
        self.capif_host = capif_host
        self.capif_https_port = capif_https_port
        self.folder_to_store_certificates_and_api_key = os.path.join(
            folder_path_for_certificates_and_api_key.strip(), ""
        )
        self.capif_api_details = self.__load_netapp_api_details()
        self.signed_key_crt_path = (
                self.folder_to_store_certificates_and_api_key
                + self.capif_api_details["csr_common_name"] + ".crt"
        )
        self.private_key_path = self.folder_to_store_certificates_and_api_key + "private.key"
        self.ca_root_path = self.folder_to_store_certificates_and_api_key + "ca.crt"
        self.logger.info("ServiceDiscoverer inicializado correctamente")

    def get_api_invoker_id(self):
        return self.capif_api_details["api_invoker_id"]

    def __load_netapp_api_details(self):
        try:
            with open(
                    self.folder_to_store_certificates_and_api_key + "capif_api_security_context_details.json",
                    "r",
            ) as openfile:
                details = json.load(openfile)
            self.logger.info("Detalles de la API de NetApp cargados correctamente")
            return details
        except Exception as e:
            self.logger.error("Error al cargar detalles de la API de NetApp: %s", str(e))
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
        self.logger.info("Obteniendo el token de acceso para api_name=%s, api_id=%s, aef_id=%s", api_name, api_id, aef_id)

        if self.__security_context_does_not_exist():
            self.logger.info("No existe un contexto de seguridad. Registrando un nuevo servicio de seguridad.")
            self.capif_api_details["registered_security_contexes"] = []
            self.capif_api_details["registered_security_contexes"].append({"api_id": api_id, "aef_id": aef_id})
            self.__register_security_service(api_id, aef_id)
            self.__cache_security_context()
        elif self.__security_context_for_given_api_id_and_aef_id_does_not_exist(api_id, aef_id):
            self.logger.info("El contexto de seguridad para api_id=%s y aef_id=%s no existe. Actualizando el servicio de seguridad.", api_id, aef_id)
            self.capif_api_details["registered_security_contexes"].append({"api_id": api_id, "aef_id": aef_id})
            self.__update_security_service(api_id, aef_id)
            self.__cache_security_context()

        token_dic = self.__get_security_token(api_name, aef_id)
        self.logger.info("Token de acceso obtenido correctamente")
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
            self.logger.info("Contexto de seguridad cacheado correctamente")
        except Exception as e:
            self.logger.error("Error al cachear el contexto de seguridad: %s", str(e))
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
            self.logger.info("Servicio de seguridad registrado correctamente")
        except requests.RequestException as e:
            self.logger.error("Error al registrar el servicio de seguridad: %s", str(e))
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
            self.logger.info("Token de seguridad obtenido correctamente")
            return response_payload
        except requests.RequestException as e:
            self.logger.error("Error al obtener el token de seguridad: %s", str(e))
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
            self.logger.info("APIs de servicio descubiertos correctamente")
            return response_payload
        except requests.RequestException as e:
            self.logger.error("Error al descubrir los APIs de servicio: %s", str(e))
            raise

    def retrieve_api_description_by_name(self, api_name):
        """
        Recupera la descripción del API por nombre.
        :param api_name: Nombre del API
        :return: Descripción del API
        """
        self.logger.info("Recuperando la descripción del API para api_name=%s", api_name)
        capif_apifs = self.discover_service_apis()
        endpoints = [api for api in capif_apifs["serviceAPIDescriptions"] if api["apiName"] == api_name]
        if not endpoints:
            error_message = (
                f"Could not find available endpoints for api_name: {api_name}. "
                "Make sure that a) your NetApp is registered and onboarded to CAPIF and "
                "b) the NEF emulator has been registered and onboarded to CAPIF"
            )
            self.logger.error(error_message)
            raise ServiceDiscoverer.ServiceDiscovererException(error_message)
        else:
            self.logger.info("Descripción del API recuperada correctamente")
            return endpoints[0]

    def retrieve_specific_resource_name(self, api_name, resource_name):
        """
        Recupera la URL para recursos específicos dentro de los APIs.
        :param api_name: Nombre del API
        :param resource_name: Nombre del recurso
        :return: URL del recurso específico
        """
        self.logger.info("Recuperando la URL para resource_name=%s en api_name=%s", resource_name, api_name)
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
            self.logger.info("URL del recurso específico recuperada correctamente: %s", result_url)
            return result_url



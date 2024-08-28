import os
import logging
import shutil
import subprocess
from requests.auth import HTTPBasicAuth
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
    level=logging.NOTSET,  # Nivel mínimo de severidad a registrar
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

        config_file = os.path.abspath(config_file)
        # Cargar configuración desde archivo si es necesario
        config = self.__load_config_file(config_file)
        
        debug_mode = os.getenv('DEBUG_MODE', config.get('debug_mode', 'False')).strip().lower()
        if debug_mode=="false": debug_mode=False
        
        # Inicializar logger
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug_mode:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.WARNING)
            
        

        
        urllib_logger = logging.getLogger("urllib3")
        if not debug_mode:
            urllib_logger.setLevel(logging.WARNING)
        else:
            urllib_logger.setLevel(logging.DEBUG)
        
        self.logger.info("Initializing CAPIFInvokerConnector")

        # Asignar valores desde variables de entorno o desde el archivo de configuración
        
        invoker_general_folder = os.path.abspath(os.getenv('invoker_folder', config.get('invoker_folder', '')).strip())
        
        capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
        register_host = os.getenv('REGISTER_HOST', config.get('register_host', '')).strip()
        capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
        capif_register_port = str(os.getenv('CAPIF_REGISTER_PORT', config.get('capif_register_port', '')).strip())
        capif_invoker_username = os.getenv('CAPIF_INVOKER_USERNAME', config.get('capif_invoker_username', '')).strip()
        capif_invoker_password = os.getenv('CAPIF_INVOKER_PASSWORD', config.get('capif_invoker_password', '')).strip()
        capif_callback_url = os.getenv('CAPIF_CALLBACK_URL', config.get('capif_callback_url', '')).strip()
        
        csr_common_name = os.getenv('CSR_COMMON_NAME', config.get('csr_common_name', '')).strip()
        csr_organizational_unit = os.getenv('CSR_ORGANIZATIONAL_UNIT', config.get('csr_organizational_unit', '')).strip()
        csr_organization = os.getenv('CSR_ORGANIZATION', config.get('csr_organization', '')).strip()
        crs_locality = os.getenv('CRS_LOCALITY', config.get('crs_locality', '')).strip()
        csr_state_or_province_name = os.getenv('CSR_STATE_OR_PROVINCE_NAME', config.get('csr_state_or_province_name', '')).strip()
        csr_country_name = os.getenv('CSR_COUNTRY_NAME', config.get('csr_country_name', '')).strip()
        csr_email_address = os.getenv('CSR_EMAIL_ADDRESS', config.get('csr_email_address', '')).strip()
        
        self.invoker_folder=os.path.join(invoker_general_folder,capif_invoker_username)
        os.makedirs(self.invoker_folder, exist_ok=True)
        # Resto del código original para inicializar URLs y otros atributos
        

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
    
        self.capif_invoker_username = capif_invoker_username
        self.capif_invoker_password = capif_invoker_password
        
        self.csr_common_name = "invoker_" + csr_common_name
        self.csr_organizational_unit = csr_organizational_unit
        self.csr_organization = csr_organization
        self.crs_locality = crs_locality
        self.csr_state_or_province_name = csr_state_or_province_name
        self.csr_country_name = csr_country_name
        self.csr_email_address = csr_email_address
        self.capif_api_details_filename = "capif_api_security_context_details-"+self.capif_invoker_username+".json"
        #self.capif_api_details = self.__load_invoker_api_details()
        
        self.logger.info("CAPIFInvokerConnector initialized with the config.json parameters")

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
            self.__write_to_file( api_invoker_id, capif_discover_url)
            self.logger.info("Invoker registered and onboarded successfully")
        except Exception as e:
            self.logger.error(f"Error during Invoker registration and onboarding: {e}")
            raise

    def __load_invoker_api_details(self):
        self.logger.info("Loading Invoker API details")
        path = os.path.join(
            self.invoker_folder, 
            self.capif_api_details_filename
        )
        with open(
            path, "r"
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

            signed_key_crt_path = os.path.join(
                self.invoker_folder, 
                capif_api_details["user_name"] + ".crt"
            )

            private_key_path = os.path.join(
                self.invoker_folder, 
                "private.key"
            )

            path = os.path.join(
                self.invoker_folder, 
                "ca.crt"
            )
            response = requests.request(
                "DELETE",
                url,
                cert=(signed_key_crt_path, private_key_path),
                verify=path,
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
            self.__remove_files()
            self.logger.info("Invoker offboarded and deregistered successfully")
        except Exception as e:
            self.logger.error(f"Error during Invoker offboarding and deregistering: {e}")
            raise

    def __create_private_and_public_keys(self) -> str:
        self.logger.info("Creating private and public keys for the Invoker cert")
        try:
            private_key_path = os.path.join(self.invoker_folder, "private.key")
            
            csr_file_path = os.path.join(self.invoker_folder, "cert_req.csr")

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

   

    def __remove_files(self):
        self.logger.info("Removing files generated")
        try:
            folder_path = self.invoker_folder
            
            if os.path.exists(folder_path):
                # Elimina todo el contenido dentro de la carpeta, incluyendo archivos y subcarpetas
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        os.remove(os.path.join(root, file))
                    for dir in dirs:
                        shutil.rmtree(os.path.join(root, dir))
                os.rmdir(folder_path)
                self.logger.info(f"All contents in {folder_path} removed successfully.")
            else:
                self.logger.warning(f"Folder {folder_path} does not exist.")
        except Exception as e:
            self.logger.error(f"Error during removing folder contents: {e}")
            raise

    

    
    def __save_capif_ca_root_file_and_get_auth_token(self):
        self.logger.info("Saving CAPIF CA root file and getting auth token with user and password given by the CAPIF administrator")
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
            ca_root_file_path = os.path.join(self.invoker_folder, "ca.crt")
            ca_root_file = open(ca_root_file_path, "wb+")
            ca_root_file.write(bytes(response_payload["ca_root"], "utf-8"))
            self.logger.info("CAPIF CA root file saved and auth token obtained successfully")
            return response_payload
        except Exception as e:
            self.logger.error(f"Error during saving CAPIF CA root file and getting auth token: {e}")
            raise

    def __onboard_invoker_to_capif_and_create_the_signed_certificate(
        self, public_key, capif_onboarding_url, capif_access_token
    ):
        self.logger.info("Onboarding Invoker to CAPIF and creating signed certificate by giving our public key to CAPIF")
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
            pathca = os.path.join(self.invoker_folder,"ca.crt")
            response = requests.request(
                "POST",
                url,
                headers=headers,
                data=payload,
                verify=pathca,
            )
            response.raise_for_status()
            response_payload = json.loads(response.text)
            name=self.capif_invoker_username+".crt"
            pathcsr = os.path.join(self.invoker_folder, name)
            certification_file = open(
                pathcsr, "wb"
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

    def __write_to_file(self, api_invoker_id, discover_services_url):
        self.logger.info("Writing API invoker ID and service discovery URL to file")
        path = os.path.join(self.invoker_folder, self.capif_api_details_filename)
        try:
            with open(
                path, "w"
            ) as outfile:
                json.dump(
                    {
                        "user_name": self.capif_invoker_username,
                        "api_invoker_id": api_invoker_id,
                        "discover_services_url": discover_services_url,
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
    def __init__(self, config_file: str):
        """
        Inicializa el conector CAPIFProvider con los parámetros especificados en el archivo de configuración.
        """
        # Cargar configuración desde archivo si es necesario
        config_file = os.path.abspath(config_file)
        self.config_path = os.path.dirname(config_file)+"/"
        config = self.__load_config_file(config_file)
        debug_mode = os.getenv('DEBUG_MODE', config.get('debug_mode', 'False')).strip().lower()
        if debug_mode=="false": debug_mode=False
        # Inicializar logger
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug_mode:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.WARNING)
            
        
        
        
        urllib_logger = logging.getLogger("urllib3")
        if not debug_mode:
            urllib_logger.setLevel(logging.WARNING)
        else:
            urllib_logger.setLevel(logging.DEBUG)
        
            
        

        try:
            
            
            provider_general_folder = os.path.abspath(os.getenv('PROVIDER_FOLDER', config.get('provider_folder', '')).strip())
            capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
            capif_register_host = os.getenv('REGISTER_HOST', config.get('register_host', '')).strip()
            capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
            capif_register_port = str(os.getenv('CAPIF_REGISTER_PORT', config.get('capif_register_port', '')).strip())
            capif_provider_username = os.getenv('CAPIF_PROVIDER_USERNAME', config.get('capif_provider_username', '')).strip()
            capif_provider_password = os.getenv('CAPIF_PROVIDER_PASSWORD', config.get('capif_provider_password', '')).strip()
            
            csr_common_name = os.getenv('CSR_COMMON_NAME', config.get('csr_common_name', '')).strip()
            csr_organizational_unit = os.getenv('CSR_ORGANIZATIONAL_UNIT', config.get('csr_organizational_unit', '')).strip()
            csr_organization = os.getenv('CSR_ORGANIZATION', config.get('csr_organization', '')).strip()
            crs_locality = os.getenv('CRS_LOCALITY', config.get('crs_locality', '')).strip()
            csr_state_or_province_name = os.getenv('CSR_STATE_OR_PROVINCE_NAME', config.get('csr_state_or_province_name', '')).strip()
            csr_country_name = os.getenv('CSR_COUNTRY_NAME', config.get('csr_country_name', '')).strip()
            csr_email_address = os.getenv('CSR_EMAIL_ADDRESS', config.get('csr_email_address', '')).strip()
            APFs = os.getenv('APFS', config.get('APFs', '')).strip()
            AEFs = os.getenv('AEFS', config.get('AEFs', '')).strip()
            

            if not capif_host:
                self.logger.warning("CAPIF_HOST is not provided; defaulting to an empty string")
            if not capif_provider_username:
                self.logger.error("CAPIF_PROVIDER_USERNAME is required but not provided")
                raise ValueError("CAPIF_PROVIDER_USERNAME is required")

            self.provider_folder = os.path.join(provider_general_folder, capif_provider_username)
            os.makedirs(self.provider_folder, exist_ok=True)
            
            self.capif_host = capif_host.strip()
            self.capif_provider_username = capif_provider_username
            self.capif_provider_password = capif_provider_password
            self.capif_register_host = capif_register_host
            self.capif_register_port = capif_register_port
            self.csr_common_name = csr_common_name
            self.csr_organizational_unit = csr_organizational_unit
            self.csr_organization = csr_organization
            self.crs_locality = crs_locality
            self.csr_state_or_province_name = csr_state_or_province_name
            self.csr_country_name = csr_country_name
            self.csr_email_address = csr_email_address
            self.AEFs = int(AEFs)
            self.APFs = int(APFs)
            
            
            self.capif_https_port = str(capif_https_port)
            
            
            if len(self.capif_https_port) == 0 or int(self.capif_https_port) == 443:
                self.capif_https_url = f"https://{capif_host.strip()}/"
            else:
                self.capif_https_url = f"https://{capif_host.strip()}:{self.capif_https_port.strip()}/"

            if len(capif_register_port) == 0:
                self.capif_register_url = f"https://{capif_register_host.strip()}:8084/"
            else:
                self.capif_register_url = f"https://{capif_register_host.strip()}:{capif_register_port.strip()}/"

            self.logger.info("CAPIFProviderConnector initialized with the config.json parameters")
        
        except Exception as e:
            self.logger.error(f"Error during initialization: {e}")
            raise

    

    def __store_certificate(self) -> None:
        # Retrieves and stores the cert_server.pem from CAPIF.
        self.logger.info("Retrieving capif_cert_server.pem, this may take a few minutes.")

        cmd = f"openssl s_client -connect {self.capif_host}:{self.capif_https_port} | openssl x509 -text > {self.provider_folder}/capif_cert_server.pem"
        
        try:
            # Redirige la salida estándar y de errores a os.devnull para ocultar los logs
            with open(os.devnull, 'w') as devnull:
                subprocess.run(cmd, shell=True, check=True, stdout=devnull, stderr=devnull)
            
            cert_file = os.path.join(self.provider_folder, "capif_cert_server.pem")
            if os.path.exists(cert_file) and os.path.getsize(cert_file) > 0:
                self.logger.info("cert_server.pem successfully generated!")
            else:
                self.logger.error("Failed to generate cert_server.pem.")
                raise FileNotFoundError(f"Certificate file not found at {cert_file}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error occurred: {e}")
            raise


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
        Creates private and public keys in the certificates folder.
        :return: The contents of the public key
        """
        private_key_path = os.path.join(self.provider_folder, f"{api_prov_func_role}_private_key.key")
        csr_file_path = os.path.join(self.provider_folder, f"{api_prov_func_role}_public.csr")

        # Create key pair
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        # Create CSR
        req = X509Req()
        subject = req.get_subject()
        subject.CN = api_prov_func_role.lower()
        subject.O = self.csr_organization
        subject.OU = self.csr_organizational_unit
        subject.L = self.crs_locality
        subject.ST = self.csr_state_or_province_name
        subject.C = self.csr_country_name
        subject.emailAddress = self.csr_email_address

        req.set_pubkey(key)
        req.sign(key, "sha256")

        # Write CSR and private key to files
        with open(csr_file_path, "wb") as csr_file:
            public_key = dump_certificate_request(FILETYPE_PEM, req)
            csr_file.write(public_key)
            
        with open(private_key_path, "wb") as private_key_file:
            private_key_file.write(dump_privatekey(FILETYPE_PEM, key))

        return public_key

    def __onboard_exposer_to_capif(self, access_token, capif_onboarding_url):
        self.logger.info("Onboarding Provider to CAPIF and waiting signed certificate by giving our public keys to CAPIF")

        url = f"{self.capif_https_url}{capif_onboarding_url}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        # Crear la lista de roles sin indexar
        roles = ["AMF"]
        for n in range(1, self.AEFs + 1):
            roles.append("AEF")

        for n in range(1, self.APFs + 1):
            roles.append("APF")

        # Construir el payload con los roles sin indexar
        payload = {
            "apiProvFuncs": [
                {"regInfo": {"apiProvPubKey": ""}, "apiProvFuncRole": role, "apiProvFuncInfo": f"{role.lower()}"}
                for role in roles
            ],
            "apiProvDomInfo": "This is provider",
            "suppFeat": "fff",
            "failReason": "string",
            "regSec": access_token,
        }

        # Generar los roles indexados para la creación de certificados
        indexedroles = ["AMF"]
        for n in range(1, self.AEFs + 1):
            indexedroles.append(f"AEF-{n}")

        for n in range(1, self.APFs + 1):
            indexedroles.append(f"APF-{n}")

        # Guardar las claves públicas y generar los certificados con roles indexados
        for i, api_func in enumerate(payload["apiProvFuncs"]):
            # Generar las claves públicas con el rol indexado, pero no actualizar el payload con el rol indexado
            public_key = self.__create_private_and_public_keys(indexedroles[i])
            
            # Asignar la clave pública al payload
            api_func["regInfo"]["apiProvPubKey"] = public_key.decode("utf-8")


        try:
            response = requests.post(
                url,
                headers=headers,
                data=json.dumps(payload),
                verify=os.path.join(self.provider_folder, "ca.crt"),
            )
            response.raise_for_status()
            self.logger.info("Provider onboarded and signed certificate obtained successfully")
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Onboarding failed: {e}")
            raise
   
    
    def __write_to_file(self, onboarding_response, capif_registration_id, publish_url):
        self.logger.info("Saving the most relevant onboarding data")

        # Generar los roles indexados para la correspondencia
        indexedroles = ["AMF"]
        for n in range(1, self.AEFs + 1):
            indexedroles.append(f"AEF-{n}")

        for n in range(1, self.APFs + 1):
            indexedroles.append(f"APF-{n}")

        # Guardar los certificados con los nombres indexados
        for i, func_profile in enumerate(onboarding_response["apiProvFuncs"]):
            role = indexedroles[i].lower()
            cert_path = os.path.join(self.provider_folder, f"{role}.crt")
            with open(cert_path, "wb") as cert_file:
                cert_file.write(func_profile["regInfo"]["apiProvCert"].encode("utf-8"))

        # Guardar los detalles del proveedor
        provider_details_path = os.path.join(self.provider_folder, "capif_provider_details.json")
        with open(provider_details_path, "w") as outfile:
            data = {
                "capif_registration_id": capif_registration_id,
                "publish_url": publish_url,
                **{f"{indexedroles[i]}_api_prov_func_id": api_prov_func["apiProvFuncId"]
                for i, api_prov_func in enumerate(onboarding_response["apiProvFuncs"])}
            }
            json.dump(data, outfile, indent=4)

        self.logger.info("Data saved")


    
 
    def __save_capif_ca_root_file_and_get_auth_token(self):
        url = f"{self.capif_register_url}getauth"
        self.logger.info("Saving CAPIF CA root file and getting auth token with user and password given by the CAPIF administrator")

        try:
            response = requests.get(
                url,
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth(self.capif_provider_username, self.capif_provider_password),
                verify=False
            )
            response.raise_for_status()

            self.logger.info("Authorization acquired successfully")

            response_payload = response.json()
            ca_root_file_path = os.path.join(self.provider_folder, "ca.crt")

            with open(ca_root_file_path, "wb") as ca_root_file:
                ca_root_file.write(response_payload["ca_root"].encode("utf-8"))

            self.logger.info("CAPIF CA root file saved and auth token obtained successfully")
            return response_payload

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error acquiring authorization: {e}")
            raise

    
    def register_and_onboard_provider(self) -> None:
        """
        Retrieves and stores the certificate from CAPIF, acquires authorization, and registers the provider.
        """
        # Store the certificate
        self.__store_certificate()
        
        # Retrieve CA root file and get authorization token
        capif_postauth_info = self.__save_capif_ca_root_file_and_get_auth_token()

        # Extract necessary information
        capif_onboarding_url = capif_postauth_info["ccf_api_onboarding_url"]
        access_token = capif_postauth_info["access_token"]
        ccf_publish_url = capif_postauth_info["ccf_publish_url"]

        # Onboard provider to CAPIF
        onboarding_response = self.__onboard_exposer_to_capif(
            access_token, capif_onboarding_url
        )

        # Save onboarding details to file
        capif_registration_id = onboarding_response["apiProvDomId"]
        self.__write_to_file(
            onboarding_response, capif_registration_id, ccf_publish_url
        )



    def publish_services(self, service_api_description_json_full_path: str) -> dict:
        """
        Publishes services to CAPIF and returns the published services dictionary.

        :param service_api_description_json_full_path: The full path of the service_api_description.json containing
        the endpoints to be published.
        :return: The published services dictionary that was saved in CAPIF.
        """
        self.logger.info("Starting the service publication process")

        # Load provider details
        provider_details_path = os.path.join(self.provider_folder, "capif_provider_details.json")
        self.logger.info(f"Loading provider details from {provider_details_path}")
        
        provider_details=self.__load_provider_api_details()
        publish_url=provider_details["publish_url"]

        json_path = self.config_path + "publish.json"
        

        # Leer el archivo publish.json
        with open(json_path, 'r') as f:
            chosenAPFsandAEFs = json.load(f)

        APF_api_prov_func_id = chosenAPFsandAEFs["publisherAPFid"]
        AEFs_list = chosenAPFsandAEFs["publisherAEFsids"]

        apf_number = None
        for key, value in provider_details.items():
            if value == APF_api_prov_func_id and key.startswith("APF-"):
                apf_inter = key.split("-")[1]
                apf_number= apf_inter.split("_")[0]                                 # Obtener el número del APF
                break

        if apf_number is None:
            self.logger.error(f"No matching APF found for publisherAPFid: {APF_api_prov_func_id}")
            raise ValueError("Invalid publisherAPFid")

        # Leer y modificar la descripción de la API de servicio
        self.logger.info(f"Reading and modifying service API description from {service_api_description_json_full_path}")

        try:
            with open(service_api_description_json_full_path, "r") as service_file:
                data = json.load(service_file)

                # Verificamos que el número de AEFs coincide con el número de perfiles
                if len(AEFs_list) != len(data.get("aefProfiles", [])):
                    self.logger.error("The number of AEFs in publisherAEFsids does not match the number of profiles in aefProfiles")
                    raise ValueError("Mismatch between number of AEFs and profiles")

                # Asignamos los AEFs correspondientes
                for profile, aef_id in zip(data.get("aefProfiles", []), AEFs_list):
                    profile["aefId"] = aef_id

                self.logger.info("Service API description modified successfully")

                # Guardamos los cambios en el archivo
                with open(service_api_description_json_full_path, "w") as service_file:
                    json.dump(data, service_file, indent=4)

        except FileNotFoundError:
            self.logger.error(f"Service API description file not found: {service_api_description_json_full_path}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON from file {service_api_description_json_full_path}: {e}")
            raise
        except ValueError as e:
            self.logger.error(f"Error with the input data: {e}")
            raise

        # Publish services
        url = f"{self.capif_https_url}{publish_url.replace('<apfId>', APF_api_prov_func_id)}"
        cert = (
            os.path.join(self.provider_folder, f"apf-{apf_number}.crt"),
            os.path.join(self.provider_folder, f"apf-{apf_number}_private_key.key"),
        )
        
        self.logger.info(f"Publishing services to URL: {url}")
        
        try:
            response = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(data),
                cert=cert,
                verify=os.path.join(self.provider_folder, "ca.crt"),
            )
            response.raise_for_status()
            self.logger.info("Services published successfully")

            # Save response to file
            capif_response = response.text
            file_name = os.path.basename(service_api_description_json_full_path)
            output_path = os.path.join(self.provider_folder, f"CAPIF_{file_name}")
            with open(output_path, "w") as outfile:
                outfile.write(capif_response)
            self.logger.info(f"CAPIF response saved to {output_path}")

            return json.loads(capif_response)

        except requests.RequestException as e:
            self.logger.error(f"Request to CAPIF failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during service publication: {e}")
            raise

    def unpublish_service(self) -> dict:
        """
        Publishes services to CAPIF and returns the published services dictionary.

        :param service_api_description_json_full_path: The full path of the service_api_description.json containing
        the endpoints to be published.
        :return: The published services dictionary that was saved in CAPIF.
        """
        self.logger.info("Starting the service unpublication process")
        provider_details_path = os.path.join(self.provider_folder, "capif_provider_details.json")
        self.logger.info(f"Loading provider details from {provider_details_path}")
        
        provider_details=self.__load_provider_api_details()
        publish_url=provider_details["publish_url"]

        # Load provider details
        json_path = self.config_path +"publish.json"
        with open(json_path, 'r') as f:
            publish = json.load(f)
        api_id="/" + publish["serviceApiId"]
        APF_api_prov_func_id=publish["publisherAPFid"]

        apf_number = None
        for key, value in provider_details.items():
            if value == APF_api_prov_func_id and key.startswith("APF-"):
                apf_inter = key.split("-")[1]
                apf_number= apf_inter.split("_")[0]                                 # Obtener el número del APF
                break

        if apf_number is None:
            self.logger.error(f"No matching APF found for publisherAPFid: {APF_api_prov_func_id}")
            raise ValueError("Invalid publisherAPFid")

        
        self.logger.info(f"Loading provider details from {provider_details_path}")
        
        

        

        url = f"{self.capif_https_url}{publish_url.replace('<apfId>', APF_api_prov_func_id)}{api_id}"

        cert = (
            os.path.join(self.provider_folder, f"apf-{apf_number}.crt"),
            os.path.join(self.provider_folder, f"apf-{apf_number}_private_key.key"),
        )
        
        
        self.logger.info(f"Unpublishing service to URL: {url}")

        try:
            response = requests.delete(
                url,
                headers={"Content-Type": "application/json"},
                cert=cert,
                verify=os.path.join(self.provider_folder, "ca.crt"),
            )
            
            response.raise_for_status()
            self.logger.info("Services unpublished successfully")

           
        except requests.RequestException as e:
            self.logger.error(f"Request to CAPIF failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during service unpublication: {e}")
            raise

    def get_service(self) -> dict:
        """
        Publishes services to CAPIF and returns the published services dictionary.

        :param service_api_description_json_full_path: The full path of the service_api_description.json containing
        the endpoints to be published.
        :return: The published services dictionary that was saved in CAPIF.
        """
        self.logger.info("Starting the service unpublication process")

        provider_details_path = os.path.join(self.provider_folder, "capif_provider_details.json")
        self.logger.info(f"Loading provider details from {provider_details_path}")
        
        provider_details=self.__load_provider_api_details()
        publish_url=provider_details["publish_url"]

        json_path = self.config_path + "publish.json"
        

        # Leer el archivo publish.json
        with open(json_path, 'r') as f:
            chosenAPFsandAEFs = json.load(f)

        APF_api_prov_func_id = chosenAPFsandAEFs["publisherAPFid"]
        AEFs_list = chosenAPFsandAEFs["publisherAEFsids"]
        api_id="/" +chosenAPFsandAEFs["serviceApiId"]
        
        apf_number = None
        for key, value in provider_details.items():
            if value == APF_api_prov_func_id and key.startswith("APF-"):
                apf_inter = key.split("-")[1]
                apf_number= apf_inter.split("_")[0]                                 # Obtener el número del APF
                break

        if apf_number is None:
            self.logger.error(f"No matching APF found for publisherAPFid: {APF_api_prov_func_id}")
            raise ValueError("Invalid publisherAPFid")

        url = f"{self.capif_https_url}{publish_url.replace('<apfId>', APF_api_prov_func_id)}{api_id}"

        cert = (
            os.path.join(self.provider_folder, f"apf-{apf_number}.crt"),
            os.path.join(self.provider_folder, f"apf-{apf_number}_private_key.key"),
        )
        
        
        self.logger.info(f"Getting service to URL: {url}")

        try:
            response = requests.get(
                url,
                headers={"Content-Type": "application/json"},
                cert=cert,
                verify=os.path.join(self.provider_folder, "ca.crt"),
            )
            
            response.raise_for_status()
            
            self.logger.info("Service received successfully")
            path=os.path.join(self.provider_folder,"service_received.json")
            with open(path, 'w') as f:
                json_data = json.loads(response.text)
                json.dump(json_data,f,indent=4)
            self.logger.info(f"Service saved in {path}")

            

           
        except requests.RequestException as e:
            self.logger.error(f"Request to CAPIF failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during service getter: {e}")
            raise

    def get_all_services(self) -> dict:
        """
        Publishes services to CAPIF and returns the published services dictionary.

        :param service_api_description_json_full_path: The full path of the service_api_description.json containing
        the endpoints to be published.
        :return: The published services dictionary that was saved in CAPIF.
        """
        self.logger.info("Starting the service publication process")

       # Load provider details
        provider_details_path = os.path.join(self.provider_folder, "capif_provider_details.json")
        self.logger.info(f"Loading provider details from {provider_details_path}")
        
        provider_details=self.__load_provider_api_details()
        publish_url=provider_details["publish_url"]

        json_path = self.config_path + "publish.json"
        

        # Leer el archivo publish.json
        with open(json_path, 'r') as f:
            chosenAPFsandAEFs = json.load(f)

        APF_api_prov_func_id = chosenAPFsandAEFs["publisherAPFid"]
        AEFs_list = chosenAPFsandAEFs["publisherAEFsids"]

        apf_number = None
        for key, value in provider_details.items():
            if value == APF_api_prov_func_id and key.startswith("APF-"):
                apf_inter = key.split("-")[1]
                apf_number= apf_inter.split("_")[0]                                 # Obtener el número del APF
                break

        if apf_number is None:
            self.logger.error(f"No matching APF found for publisherAPFid: {APF_api_prov_func_id}")
            raise ValueError("Invalid publisherAPFid")

        # Leer y modificar la descripción de la API de servicio
        

        # Publish services
        url = f"{self.capif_https_url}{publish_url.replace('<apfId>', APF_api_prov_func_id)}"
        cert = (
            os.path.join(self.provider_folder, f"apf-{apf_number}.crt"),
            os.path.join(self.provider_folder, f"apf-{apf_number}_private_key.key"),
        )
        
        
        self.logger.info(f"Getting services to URL: {url}")

        try:
            response = requests.get(
                url,
                headers={"Content-Type": "application/json"},
                cert=cert,
                verify=os.path.join(self.provider_folder, "ca.crt"),
            )
            response.raise_for_status()
            self.logger.info("Services received successfully")

            path=os.path.join(self.provider_folder,"service_received.json")
            with open(path, 'w') as f:
                json_data = json.loads(response.text)
                json.dump(json_data,f,indent=4)
            self.logger.info(f"Services saved in {path}")

            # Save response to file
            

            

        except requests.RequestException as e:
            self.logger.error(f"Request to CAPIF failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during services reception: {e}")
            raise

    def update_service(self, service_api_description_json_full_path: str) -> dict:
        """
        Publishes services to CAPIF and returns the published services dictionary.

        :param service_api_description_json_full_path: The full path of the service_api_description.json containing
        the endpoints to be published.
        :return: The published services dictionary that was saved in CAPIF.
        """
        self.logger.info("Starting the service publication process")

        # Load provider details
        # Load provider details
        provider_details_path = os.path.join(self.provider_folder, "capif_provider_details.json")
        self.logger.info(f"Loading provider details from {provider_details_path}")
        
        provider_details=self.__load_provider_api_details()
        publish_url=provider_details["publish_url"]

        json_path = self.config_path + "publish.json"
        

        # Leer el archivo publish.json
        with open(json_path, 'r') as f:
            chosenAPFsandAEFs = json.load(f)

        APF_api_prov_func_id = chosenAPFsandAEFs["publisherAPFid"]
        AEFs_list = chosenAPFsandAEFs["publisherAEFsids"]

        apf_number = None
        for key, value in provider_details.items():
            if value == APF_api_prov_func_id and key.startswith("APF-"):
                apf_inter = key.split("-")[1]
                apf_number= apf_inter.split("_")[0]                                 # Obtener el número del APF
                break

        if apf_number is None:
            self.logger.error(f"No matching APF found for publisherAPFid: {APF_api_prov_func_id}")
            raise ValueError("Invalid publisherAPFid")

        # Leer y modificar la descripción de la API de servicio
        self.logger.info(f"Reading and modifying service API description from {service_api_description_json_full_path}")

        try:
            with open(service_api_description_json_full_path, "r") as service_file:
                data = json.load(service_file)

                # Verificamos que el número de AEFs coincide con el número de perfiles
                if len(AEFs_list) != len(data.get("aefProfiles", [])):
                    self.logger.error("The number of AEFs in publisherAEFsids does not match the number of profiles in aefProfiles")
                    raise ValueError("Mismatch between number of AEFs and profiles")

                # Asignamos los AEFs correspondientes
                for profile, aef_id in zip(data.get("aefProfiles", []), AEFs_list):
                    profile["aefId"] = aef_id

                self.logger.info("Service API description modified successfully")

                # Guardamos los cambios en el archivo
                with open(service_api_description_json_full_path, "w") as service_file:
                    json.dump(data, service_file, indent=4)

        except FileNotFoundError:
            self.logger.error(f"Service API description file not found: {service_api_description_json_full_path}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON from file {service_api_description_json_full_path}: {e}")
            raise
        except ValueError as e:
            self.logger.error(f"Error with the input data: {e}")
            raise
        api_id="/" +chosenAPFsandAEFs["serviceApiId"]
        # Publish services
        url = f"{self.capif_https_url}{publish_url.replace('<apfId>', APF_api_prov_func_id)}{api_id}"
        cert = (
            os.path.join(self.provider_folder, f"apf-{apf_number}.crt"),
            os.path.join(self.provider_folder, f"apf-{apf_number}_private_key.key"),
        )
        
        
        self.logger.info(f"Publishing services to URL: {url}")

        try:
            response = requests.put(
                url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(data),
                cert=cert,
                verify=os.path.join(self.provider_folder, "ca.crt"),
            )
            response.raise_for_status()
            self.logger.info("Services updated successfully")

            # Save response to file
            capif_response = response.text
            file_name = os.path.basename(service_api_description_json_full_path)
            output_path = os.path.join(self.provider_folder, f"CAPIF_{file_name}")
            with open(output_path, "w") as outfile:
                outfile.write(capif_response)
            self.logger.info(f"CAPIF response saved to {output_path}")

            return json.loads(capif_response)

        except requests.RequestException as e:
            self.logger.error(f"Request to CAPIF failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during service publication: {e}")
            raise

    def offboard_and_deregister_nef(self) -> None:
        """
        Offboards and deregisters the NEF (Network Exposure Function).
        """
        try:
            self.offboard_nef()
            self.__remove_files()
            self.logger.info("Provider offboarded and deregistered successfully.")
        except Exception as e:
            self.logger.error(f"Failed to offboard and deregister Provider: {e}")
            raise
        
    def offboard_nef(self) -> None:
        """
        Offboards the NEF (Network Exposure Function) from CAPIF.
        """
        try:
            self.logger.info("Offboarding the provider")
            
            # Load CAPIF API details
            capif_api_details = self.__load_provider_api_details()
            url = f"{self.capif_https_url}api-provider-management/v1/registrations/{capif_api_details['capif_registration_id']}"

            # Define certificate paths
            cert_paths = (
                os.path.join(self.provider_folder, "amf.crt"),
                os.path.join(self.provider_folder, "AMF_private_key.key")
            )

            # Send DELETE request to offboard the provider
            response = requests.delete(
                url,
                cert=cert_paths,
                verify=os.path.join(self.provider_folder, "ca.crt")
            )
            
            response.raise_for_status()
            self.logger.info("Offboarding performed successfully")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error offboarding NEF: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            raise
    
    def __remove_files(self):
        self.logger.info("Removing files generated")
        try:
            folder_path = self.provider_folder
            
            if os.path.exists(folder_path):
                # Elimina todo el contenido dentro de la carpeta, incluyendo archivos y subcarpetas
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        os.remove(os.path.join(root, file))
                    for dir in dirs:
                        shutil.rmtree(os.path.join(root, dir))
                os.rmdir(folder_path)
                self.logger.info(f"All contents in {folder_path} removed successfully.")
            else:
                self.logger.warning(f"Folder {folder_path} does not exist.")
        except Exception as e:
            self.logger.error(f"Error during removing folder contents: {e}")
            raise

    def __load_provider_api_details(self) -> dict:
        """
        Loads NEF API details from the CAPIF provider details JSON file.
        
        :return: A dictionary containing NEF API details.
        :raises FileNotFoundError: If the CAPIF provider details file is not found.
        :raises json.JSONDecodeError: If there is an error decoding the JSON file.
        """
        file_path = os.path.join(self.provider_folder, "capif_provider_details.json")
        
        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding JSON from file {file_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error while loading NEF API details: {e}")
            raise

    
    
 
class ServiceDiscoverer:
    class ServiceDiscovererException(Exception):
        pass

    def __init__(
            self,
            config_file
    ):
        # Cargar configuración desde archivo si es necesario
        config_file = os.path.abspath(config_file)
        config = self.__load_config_file(config_file)
        debug_mode = os.getenv('DEBUG_MODE', config.get('debug_mode', 'False')).strip().lower()
        if debug_mode=="false": debug_mode=False
        
        # Inicializar logger
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug_mode:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.WARNING)
            
        
        
        
        urllib_logger = logging.getLogger("urllib3")
        if not debug_mode:
            urllib_logger.setLevel(logging.WARNING)
        else:
            urllib_logger.setLevel(logging.DEBUG)

        self.config_path = os.path.dirname(config_file)+"/"
        capif_host = os.getenv('CAPIF_HOST', config.get('capif_host', '')).strip()
        capif_https_port = str(os.getenv('CAPIF_HTTPS_PORT', config.get('capif_https_port', '')).strip())
        invoker_general_folder = os.path.abspath(os.getenv('invoker_folder', config.get('invoker_folder', '')).strip())

        capif_invoker_username = os.getenv('CAPIF_INVOKER_USERNAME', config.get('capif_invoker_username', '')).strip()

        
        self.capif_invoker_username=capif_invoker_username
        self.capif_host = capif_host
        self.capif_https_port = capif_https_port
        self.invoker_folder = os.path.join(
            invoker_general_folder, capif_invoker_username
        )
        os.makedirs(self.invoker_folder, exist_ok=True)
        self.capif_api_details = self.__load_provider_api_details()
        
        self.signed_key_crt_path = os.path.join(
                self.invoker_folder
                ,self.capif_api_details["user_name"] + ".crt"
        )
        self.private_key_path = os.path.join(self.invoker_folder ,"private.key")
        self.ca_root_path = os.path.join(self.invoker_folder , "ca.crt")
        
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
            path=os.path.join(self.invoker_folder,"capif_api_security_context_details-"+self.capif_invoker_username+".json")
            with open(
                    path,
                    "r",
            ) as openfile:
                details = json.load(openfile)
            self.logger.info("Api provider details correctly loaded")
            return details
        except Exception as e:
            self.logger.error("Error while loading Api invoker details: %s", str(e))
            raise

    def _add_trailing_slash_to_url_if_missing(self, url):
        if not url.endswith("/"):
            url += "/"
        return url

    def get_security_context(self):
        self.logger.info("Getting security context for all API's filtered")
        
           
        
        self.logger.info("Trying to update security context")
        self.__update_security_service()
        self.__cache_security_context()


    def get_access_token(self):
        """
        :param api_name: El nombre del API devuelto por descubrir servicios
        :param api_id: El id del API devuelto por descubrir servicios
        :param aef_id: El aef_id relevante devuelto por descubrir servicios
        :return: El token de acceso (jwt)
        """
        token_dic = self.__get_security_token()
        self.logger.info("Access token successfully obtained")
        return token_dic["access_token"]

    

    def __cache_security_context(self):
        try:
            path=os.path.join(self.invoker_folder,"capif_api_security_context_details-"+self.capif_invoker_username+".json")
            with open(
                    path, "w"
            ) as outfile:
                json.dump(self.capif_api_details, outfile)
            self.logger.info("Security context saved correctly")
        except Exception as e:
            self.logger.error("Error when saving the security context: %s", str(e))
            raise

    def __update_security_service(self):
        """
        Actualiza el servicio de seguridad.
        
        :param api_id: El id del API devuelto por descubrir servicios.
        :param aef_id: El aef_id devuelto por descubrir servicios.
        :return: None.
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

        number_of_apis = len(self.capif_api_details["registered_security_contexes"])

        for i in range(0, number_of_apis):
            # Obteniendo los valores de api_id y aef_id para cada API
            api_id = self.capif_api_details["registered_security_contexes"][i]["api_id"]
            aef_id = self.capif_api_details["registered_security_contexes"][i]["aef_id"]
            
            security_info = {
                "prefSecurityMethods": ["Oauth"],
                "authenticationInfo": "string",
                "authorizationInfo": "string",
                "aefId": aef_id,
                "apiId": api_id
            }
            
            payload["securityInfo"].append(security_info)

        try:
            response = requests.post(url,
                                    json=payload,
                                    cert=(self.signed_key_crt_path, self.private_key_path),
                                    verify=self.ca_root_path)
            response.raise_for_status()
            self.logger.info("Security context correctly updated")
        
        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 404:
                self.logger.warning("Received 404 error, redirecting to register security service")
                self.__register_security_service()
            else:
                self.logger.error("HTTP error occurred: %s", str(http_err))
                raise

        except requests.RequestException as e:
            self.logger.error("Error trying to update Security context: %s", str(e))
            raise


    def __register_security_service(self):
        """
        :param api_id: El id del API devuelto por descubrir servicios
        :param aef_id: El aef_id devuelto por descubrir servicios
        :return: None
        """

        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/trustedInvokers/{self.capif_api_details['api_invoker_id']}"
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

        number_of_apis = len(self.capif_api_details["registered_security_contexes"])



        for i in range(0,number_of_apis):
        # Obteniendo los valores de api_id y aef_id para cada API
            api_id = self.capif_api_details["registered_security_contexes"][i]["api_id"]
            aef_id = self.capif_api_details["registered_security_contexes"][i]["aef_id"]
        
            security_info = {
                "prefSecurityMethods": ["Oauth"],
                "authenticationInfo": "string",
                "authorizationInfo": "string",
                "aefId": aef_id,
                "apiId": api_id
            }
            
            payload["securityInfo"].append(security_info)

        
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

    def __get_security_token(self):
        """
        :param api_name: El nombre del API devuelto por descubrir servicios
        :param aef_id: El aef_id relevante devuelto por descubrir servicios
        :return: El token de acceso (jwt)
        """
        url = f"https://{self.capif_host}:{self.capif_https_port}/capif-security/v1/securities/{self.capif_api_details['api_invoker_id']}/token"
        # Construir el scope concatenando aef_id y api_name separados por un ';'
        scope_parts = []

        # Iterar sobre los contextos registrados y construir las partes del scope
        for context in self.capif_api_details["registered_security_contexes"]:
            aef_id = context["aef_id"]
            api_name = context["api_name"]
            scope_parts.append(f"{aef_id}:{api_name}")

        # Unir todas las partes del scope con ';' y añadir el prefijo '3gpp#'
        scope = "3gpp#" + ";".join(scope_parts)
        
        
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.capif_api_details["api_invoker_id"],
            "client_secret": "string",
            "scope": scope
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
        Descubre los APIs de servicio desde CAPIF con filtros basados en un archivo JSON.
        :return: Payload JSON con los detalles de los APIs de servicio
        """
        # Cargar los parámetros desde el archivo JSON
        
        json_path = self.config_path +"discover_filter.json"
        with open(json_path, 'r') as f:
            filters = json.load(f)

        # Filtrar parámetros que no sean vacíos "
        query_params = {k: v for k, v in filters.items() if v }

        # Formar la URL con los parámetros de query
        query_string = "&".join([f"{k}={v}" for k, v in query_params.items()])
        
        url = f"https://{self.capif_host}:{self.capif_https_port}/{self.capif_api_details['discover_services_url']}{self.capif_api_details['api_invoker_id']}"
        
        if query_string:
            url += f"&{query_string}"
        
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

    def save_security_token(self,token):
        self.capif_api_details["access_token"]=token
        self.__cache_security_context()

    def get_tokens(self):
        
        self.get_security_context()
        token=self.get_access_token()
        self.save_security_token(token)
        
    
    def discover(self):
        endpoints = self.discover_service_apis()
        
        if len(endpoints) > 0:
            self.save_api_discovered(endpoints)
        else:
            self.logger.error("No endpoints have been registered. Make sure a Provider has Published an API to CAPIF first")
    
    def save_api_discovered(self,endpoints):
        self.capif_api_details["registered_security_contexes"] = []
        for service in endpoints["serviceAPIDescriptions"]:
                api_name = service["apiName"]
                api_id = service["apiId"]
                for n in service["aefProfiles"]:
                    aef_id=n["aefId"]
                    self.capif_api_details["registered_security_contexes"].append({"api_name":api_name,"api_id": api_id, "aef_id": aef_id})
        self.save_api_details()        

    import json

    def save_api_details(self):
        try:
            # Define the path to save the details
            file_path = os.path.join(self.invoker_folder , "capif_api_security_context_details-" + self.capif_invoker_username + ".json")
            
            # Save the details as a JSON file
            with open(file_path, "w") as outfile:
                json.dump(self.capif_api_details, outfile, indent=4)
            
            # Log the success of the operation
            self.logger.info("API provider details correctly saved")

        except Exception as e:
            # Log any errors that occur during the save process
            self.logger.error("Error while saving API provider details: %s", str(e))
            raise

        


import json
import logging
import requests
import urllib3
import emulator_utils
from requests.auth import HTTPBasicAuth
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


logging.basicConfig(
    level=logging.INFO,  # Nivel mínimo de severidad a registrar
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Formato del mensaje de log
    handlers=[
        logging.FileHandler("register_logs.log"),  # Registra en un archivo
        logging.StreamHandler()  # También muestra en la consola
    ]
)


def main():
    
    variables=__load_config_file(config_file=emulator_utils.get_register_file())
    log_result = __log_to_capif(variables)
    admintoken = log_result["access_token"]
    postcreation = __create_user(admintoken,variables)
    uuid = postcreation["uuid"]
    __write_to_file(uuid,variables)
    logger.info(uuid)

def __log_to_capif(variables):
        logger.info("Logging in to CAPIF")
        capif_register_url="https://" + variables["register_host"].strip()+ ":" + variables["capif_register_port"] + "/"
        try:
            url = capif_register_url + "login"

            response = requests.request(
                "POST",
                url,
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth(variables["capif_register_username"], variables["capif_register_password"]),
                verify=False,
            )
            response.raise_for_status()
            response_payload = json.loads(response.text)
            logger.info("Logged in to CAPIF successfully")
            return response_payload
        except Exception as e:
            logger.error(f"Error during login to CAPIF: {e}")
            raise


def __create_user(admin_token,variables):
        logger.info("Creating user in CAPIF")
        capif_register_url="https://" + variables["register_host"].strip()+ ":" + variables["capif_register_port"] + "/"
        try:
            url = capif_register_url + "createUser"
            payload = {
                "username": variables["capif_username"],
                "password": variables["capif_password"],
                "description": "description",
                "email": "csr_email_address@tid.es",
                "enterprise": "csr_organization",
                "country": "crs_locality",
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
            logger.info("User created successfully")
            return response_payload
        except Exception as e:
            logger.error(f"Error during user creation in CAPIF: {e}")
            raise

def __load_config_file(config_file: str):
            """Carga el archivo de configuración."""
            try:
                with open(config_file, 'r') as file:
                    return json.load(file)
            except FileNotFoundError:
                logger.warning(f"Configuration file {config_file} not found. Using defaults or environment variables.")
                return {}

def __write_to_file(uuid, variables):
    logger.info("Saving uuid in config.json")
    
    # Abrimos el archivo y leemos su contenido
    with open(variables["config_path"] + "config.json", "r") as infile:
        data = json.load(infile)
    
    # Modificamos el contenido del archivo para incluir el nuevo UUID
    data["uuid"] = uuid
    
    # Escribimos el contenido actualizado de nuevo en el archivo
    with open(variables["config_path"] + "config.json", "w") as outfile:
        json.dump(data, outfile, indent=4)
    
    logger.info("Data saved")

if __name__ == "__main__":
    logger = logging.getLogger("CAPIF Register")
    logger.info("Initializing CAPIF Register")
    main()
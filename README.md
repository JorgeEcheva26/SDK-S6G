
# SDK-S6G

This tool is focused on connect to CAPIF in a simpler way.



## Functionalities

- **Invoker CAPIF Connector**: Simplifies the onboarding process for Invoker users.

- **Provider CAPIF Connector**: Simplifies the onboarding process for Provider users and includes the ability to register multiple APFs and AEFs if necessary.

- **Invoker Service Discovery**: Facilitates Discovery requests to CAPIF, stores received API services, and offers filtering options.

- **Invoker Service Token Retrieval**: After Discovery, this feature simplifies the creation of the appropriate security context for each service and acquiring access tokens to utilize the APIs.

- **Provider API Publishing**: Eases the process of publishing an API, with the option to select specific APFs and AEFs for publication.

- **Provider API Unpublishing**: Simplifies the process of removing an API.

- **Provider API Updating**: Facilitates the process of updating an API, with the option to choose specific APFs and AEFs for the update.

- **Provider API Retrieval**: Simplifies retrieving information for a specific service previously published.

- **Provider All APIs Retrieval**: Simplifies retrieving information for all services previously published.

- **Invoker CAPIF Connector Offboarding**: Facilitates the offboarding process for Invoker users.

- **Provider CAPIF Connector Offboarding**: Facilitates the offboarding process for Provider users.

![Descripción de la imagen](images/Flujo completo-OPENCAPIF ACTUAL.jpg)

---
## Other Functionalities

Apart from the SDK it is available diferent functionalities for development reasons

- **Register and login**: Facilitates the loggin process for admin users and creates a CAPIF user 
- **Deregister and login**: Facilitates the loggin process for admin users and eliminates a CAPIF user

![Descripción de la imagen](images/Flujo completo-SDK ACTUAL CON REGISTER.jpg)
## Installation

To use SDK-S6G we must follow this path for his Installation.

1 - Create an enviroment with pyenv

    #Comands to install the enviroment
    pyenv install 3.12
    pyenv virtualenv 3.12 Sdkenviroment

    #OPTIONAL
        #Sometimes Mac shells has a little trouble while finding the shell path, try this command
        export PATH="$HOME/.pyenv/bin:$PATH"
        eval "$(pyenv init --path)"
        eval "$(pyenv init -)"
        eval "$(pyenv virtualenv-init -)"
2 - Clone the repository
    
    git clone https://github.com/JorgeEcheva26/SDK-S6G.git

    #Then move to the SDK-S6G folder

    cd /your/path/to/SDK-S6G

3 - Install the requirements.txt file

    cd Safe-6g.egg-info

    python -m pip install --upgrade pip

    pip install -r requirements.txt

Congratulations! You ended the installation for SDK-S6G



## How to use SDK-S6G

1 - First we need to complete the emulator utils file with our absolute paths in order to complete the configuration of the SDK.The register file is not needed for the use of the SDK.The provider_exposer_get_sample_api_description_path is obligatory if we want to use the publish functionalities.

2 - Then we need to fullfill config.json

    "invoker_folder": String | The path (relative or absolute) of the folder you want to store your invoker information

    "provider_folder": String | The path (relative or absolute) of the folder you want to store your invoker information

    "capif_host": String | The domain name of your capif host

    "register_host": String | The domain name of your register host

    "capif_https_port": Integer | The port of your capif host 

    "capif_register_port": Integer | The port of your register host

    "capif_callback_url": String | The Url you want to recieve CAPIF notifications(This functionality is not currently available) 

    "csr_common_name": String | Information for your invoker certificate 

    "csr_organizational_unit": String | Information for your invoker certificate

    "csr_organization": String | Information for your invoker certificate

    "crs_locality": String | Information for your invoker certificate 

    "csr_state_or_province_name": String |Information for your invoker certificate 

    "csr_country_name": String | Information for your invoker certificate 

    "csr_email_address": String | Information for your invoker certificate

    "capif_invoker_username": String | CAPIF username 

    "capif_invoker_password": String | CAPIF password 

    "capif_provider_username": String | CAPIF username

    "capif_provider_password": String | CAPIF password

    "APFs": Integer | Number of APF's you want to onboard as a provider Example:5 

    "AEFs": Integer | Number of AEF's you want to onboard as a provider Example:2

    "debug_mode": Boolean | If you want to recieve logs from SDK-S6G Example:True/False
    



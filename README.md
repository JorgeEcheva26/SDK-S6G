
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



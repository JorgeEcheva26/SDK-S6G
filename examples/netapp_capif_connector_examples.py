import sys
import os

# Verifica si la ruta y el archivo existen
sdk_path = '/Users/IDB0128/Documents/OpenCapif/SDK-S6G/evolved5g'
sdk_file = os.path.join(sdk_path, 'sdk.py')
sys.path.append(sdk_path)


from evolved5g.sdk import CAPIFInvokerConnector, ServiceDiscoverer
import emulator_utils

def showcase_capif_connector():
    """
        This method showcases how one can use the CAPIFConnector class.
        This class is intended for use within the evolved5G Command Line interface.
        It is a low level class part of the SDK that is not required to use while creating NetApps
    """

    capif_connector = CAPIFInvokerConnector(folder_to_store_certificates=emulator_utils.get_folder_path_for_netapp_certificates_and_capif_api_key(),
                                            capif_host="capifcore",
                                            capif_http_port="8080",
                                            capif_https_port="443",
                                            capif_netapp_username="custom_netapp41",
                                            capif_netapp_password="pass123",
                                            capif_callback_url="http://localhost:5000",
                                            description= "Dummy NetApp",
                                            csr_common_name="test02",
                                            csr_organizational_unit="test_app_ou",
                                            csr_organization="test_app_o",
                                            crs_locality="Madrid",
                                            csr_state_or_province_name="Madrid",
                                            csr_country_name="ES",
                                            csr_email_address="test@example.com"
                                            )

    capif_connector.register_and_onboard_netapp()


if __name__ == "__main__":
    #Let's register NetApp to CAPIF. This should happen exactly once
    showcase_capif_connector()




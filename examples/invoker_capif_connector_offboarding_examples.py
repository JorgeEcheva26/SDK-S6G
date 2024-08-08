import sys
import os

# Agrega la ruta del archivo al sys.path
sys.path.append('/Users/IDB0128/Documents/OpenCapif/SDK-S6G')



from evolved5g.sdk import CAPIFInvokerConnector, ServiceDiscoverer
import emulator_utils

def showcase_offboard_and_deregister_netapp():
    capif_connector = CAPIFInvokerConnector(folder_to_store_certificates=emulator_utils.get_folder_path_for_netapp_certificates_and_capif_api_key(),
                                            capif_host="capifcore",
                                            register_host="localhost",
                                            capif_http_port="8080",
                                            capif_https_port="443",
                                            capif_register_port="8084",
                                            capif_netapp_username="custom_netapp69",
                                            capif_netapp_password="pass123",
                                            capif_register_username="admin",
                                            capif_register_password="password123",
                                            capif_callback_url="http://localhost:5000",
                                            description= "Dummy NetApp",
                                            csr_common_name="test03",
                                            csr_organizational_unit="test_app_ou",
                                            csr_organization="test_app_o",
                                            crs_locality="Madrid",
                                            csr_state_or_province_name="Madrid",
                                            csr_country_name="ES",
                                            csr_email_address="test@example.com"
                                            )
    capif_connector.offboard_and_deregister_netapp()
    print("COMPLETADO")


if __name__ == "__main__":
    showcase_offboard_and_deregister_netapp()



from evolved5g.sdk import CAPIFProviderConnector
import capif_exposer_utils

def offboard_capif_nef_connector():
    """

    """
    capif_connector = CAPIFProviderConnector(certificates_folder=capif_exposer_utils.nef_exposer_get_certificate_folder(),
                                             capif_host="capifcore",
                                             capif_register_host="localhost",
                                             capif_http_port="8080",
                                             capif_https_port="443",
                                             capif_register_port="8084",
                                             capif_netapp_username="test_nef_013",
                                             capif_netapp_password="testpassword",
                                             capif_register_username="admin",
                                             capif_register_password="password123",
                                             description= "test_app_description",
                                             csr_common_name="test_test_",
                                             csr_organizational_unit="test_app_ou",
                                             csr_organization="test_app_o",
                                             crs_locality="Madrid",
                                             csr_state_or_province_name="Madrid",
                                             csr_country_name="ES",
                                             csr_email_address="test@example.com"
                                             )

    capif_connector.offboard_and_deregister_nef()

    

if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    offboard_capif_nef_connector()

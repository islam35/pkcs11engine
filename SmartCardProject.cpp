/*

These codes show how to get a certificate and key from smart card.

This code blog is used to get the information(public key and certificate) from smart card.
Default password is "00000000"

Two third party dlls are using in SmartCardProject.cpp. "pkcs11engine.dll" and "pkcs11MiddlewareLibrary.dll".

pkcs11engine.dll for the "pkcs11 engine".

pkcs11MiddlewareLibrary.dll for the driver and "pkcs11 engine".

-pkcs11engine.dll is automatically installed in the directory where the program is installed. Embedded pkcs11.dll and External pkcs11.dll are used to get information from the smart card.
    -Certificate
    -Public Key infos
 -pkcs11MiddlewareLibrary.dll may come automatically when the smart card is inserted or it may be distributed by the card issuer. This dll is used to connection to the smart card.
    -Serial Number
    -Token Infos
    -Function Lists etc..

cert_info.certificate_ variable is for smart card certificate
privateKey_ is key infos
*/

EVP_PKEY* privateKey_;

    struct CertStruct
    {
        const char* s_slot_cert_id_;
        X509* certificate_;
    };

    struct CertStruct cert_info;

    typedef struct pw_cb_data {
        const void* password;
        const char* prompt_info;
    } PW_CB_DATA;
    
int getCertificateAndKey()
{
    SSL_library_init();
    SSL_load_error_strings();
    ENGINE_load_dynamic();
    ENGINE_register_all_complete();

    ENGINE* smartCardEngine = ENGINE_by_id("dynamic");
    if (smartCardEngine)
    {
        int ret = ENGINE_ctrl_cmd_string(smartCardEngine, "SO_PATH", "./pkcs11engine.dll", 0);        
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot set Engine SO_PATH.");
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }

        ret = ENGINE_ctrl_cmd_string(smartCardEngine, "ID", "pkcs11", 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot set ID.");           
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }

        ret = ENGINE_ctrl_cmd_string(smartCardEngine, "LIST_ADD", "2", 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot set LIST_ADD.");            
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }

        ret = ENGINE_ctrl_cmd_string(smartCardEngine, "LOAD", NULL, 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot LOAD Engine.");
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }

        ret = ENGINE_ctrl_cmd_string(smartCardEngine, "CLAIM_MODULE_TOKEN_FIPS", 0, 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot set CLAIM_MODULE_TOKEN_FIPS.");
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }

        ret = ENGINE_ctrl_cmd_string(smartCardEngine, "MODULE_PATH", "./pkcs11MiddlewareLibrary.dll", 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot load PKCS11 middleware library.");
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::dllNotLoaded;
        }

        ret = ENGINE_ctrl_cmd_string(smartCardEngine, "PIN", "00000000", 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot set PIN.");
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::passwordNOK;
        }

        ret = ENGINE_ctrl_cmd_string(smartCardEngine, "FORCE_LOGIN", 0, 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot run FORCE_LOGIN command.");            
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }

        // Initialize the engine
        ret = ENGINE_init(smartCardEngine);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey: Cannot Init Engine.");            
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }

        cert_info.s_slot_cert_id_ = "";
        cert_info.certificate_ = NULL;

        // Load the certificate
        // The first certificate on the smart card will be obtained.
        ret = ENGINE_ctrl_cmd(smartCardEngine, "LOAD_CERT_CTRL", 0, &cert_info, NULL, 0);
        if (!ret)
        {
            Logger::instance().gWrite("getCertificateAndKey: Cannot run LOAD_CERT_CTRL command.");
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::NoCert;
        }   

        if (checkCertificate(cert_info.certificate_) == SmartCardStatus::certExpired)
            return 0;//SmartCardStatus::certExpired;

    }

    if (smartCardEngine)
    {
        if (!ENGINE_set_default(smartCardEngine, ENGINE_METHOD_ALL))
        {
            Logger::instance().gWrite("getCertificateAndKey:  Cannot set default OpenSSL engine.");
            ENGINE_free(smartCardEngine);
            smartCardEngine = NULL;
            return 0;//SmartCardStatus::internalError;
        }
    }

    // Load the associated key.
    // The first key on the smart card will be obtained.
    PW_CB_DATA cb_data;
    privateKey_ = ENGINE_load_private_key(smartCardEngine, NULL, NULL, &cb_data);
    
    if (privateKey_ == NULL)
    {
        Logger::instance().gWrite("getCertificateAndKey:  Cannot get key from Smart Card.");
        ENGINE_free(smartCardEngine);
        smartCardEngine = NULL;
        return 0;//SmartCardStatus::NoKey;
    }

    ENGINE_free(smartCardEngine);
    ENGINE_cleanup();
    
    smartCardEngine = NULL;

    return 1;//SmartCardStatus::checkPassed;
}

main()
{
  //These codes are used for upload the infos to openssl for Mutual Authentication
  SSL_CTX_use_certificate(context->context(), cert_info.certificate_);
  SSL_CTX_use_PrivateKey(context->context(), privateKey_);
 }

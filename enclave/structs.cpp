#include "structs.h"

unsigned char *read_file(const char *filename, size_t *len = NULL);

char *convert_unsigned_char_star(unsigned char *data, size_t len) {
    char *converted = (char *) malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        converted[i] = (char) data[i];
    }
    converted[len] = '\0';
    return converted;
}

char *to_hex(const unsigned char *data, size_t len, bool little_endian = false) {
    static char const hex_map[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    int value_len = len * 2;
    char *value = (char *) malloc(value_len + 1);
    for (int i = 0; i < len; i ++) {
        char right_hex = hex_map[(unsigned int) data[i] & 0x0F];
        char left_hex = hex_map[(unsigned int) data[i] >> 4];
        if (little_endian) {
            value[2 * (len - i) - 1] = right_hex;
            value[2 * (len - i) - 2] = left_hex;
        } else {
            value[2 * i] = left_hex;
            value[2 * i + 1] = right_hex;
        }
    }
    value[value_len] = '\0';

    return value;
}

bool verify_certificate_chain(STACK_OF(X509) *certificate_chain, HopperSettings &settings, int mode) {
    size_t num_certs = sk_X509_num(certificate_chain);
    W_DEBUG("Number of certificates in the chain: %i\n", (int) num_certs);
    if (num_certs < 1) {
        W_ERROR("The certificate chain is empty.\n");
        return false;
    }
    if (mode == HopperSettings::CERT_CHAIN_VERIFICATION_MODE::GPU_ATTESTATION && num_certs != settings.MAX_CERT_CHAIN_LENGTH) {
        W_ERROR("The number of certificates fetched from the GPU is unexpected.\n");
        return false;
    }

    W_DEBUG("Store create\n");
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        W_ERROR("Failed to create a new X509 store.\n");
        return false;
    }
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        W_ERROR("Failed to create a new X509 store context.\n");
        return false;
    }
    int index = num_certs - 1;
    // Add root cert
    W_DEBUG("Adding %i certs\n", index + 1);
    X509_STORE_add_cert(store, sk_X509_value(certificate_chain, index));
    index -= 1;
    while (index > -1) {
        W_DEBUG("Cert %i\n", index);
        X509 *cert = sk_X509_value(certificate_chain, index);
        W_DEBUG("Init store context\n")
        X509_STORE_CTX_init(ctx, store, cert, NULL);
        W_DEBUG("Verify cert\n");
        // X509_print_fp(stdout, cert);
        if (X509_verify_cert(ctx) <= 0) {
            W_ERROR("Failed to verify the certificate at index %i.\n", index);
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            return false;
        }
        W_DEBUG("Cleanup\n");
        X509_STORE_CTX_cleanup(ctx);
        X509_STORE_add_cert(store, sk_X509_value(certificate_chain, index));
        index -= 1;
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return true;
}

int from_little_endian(const unsigned char *data, size_t len) {
    int num = 0;
    for (size_t i = 0; i < len; i++) {
        num += (int) (data[i] << (8 * i));
    }
    return num;
}

class DmtfMeasurement {
    private:
        struct _FieldSize {
            int DMTFSpecMeasurementValueType = 1;
            int DMTFSpecMeasurementValueSize = 2;
        } FieldSize;
        int DMTFSpecMeasurementValueType;
    public:
        int DMTFSpecMeasurementValueSize;
        unsigned char *DMTFSpecMeasurementValue;

        DmtfMeasurement(unsigned char *data, size_t data_len) {
            parse(data, data_len);
        }

        bool parse(unsigned char *data, size_t data_len) {
            unsigned char *idx_ptr = data;
            DMTFSpecMeasurementValueType = (int) *idx_ptr;
            idx_ptr += FieldSize.DMTFSpecMeasurementValueType;
            DMTFSpecMeasurementValueSize = from_little_endian(idx_ptr, FieldSize.DMTFSpecMeasurementValueSize);
            idx_ptr += FieldSize.DMTFSpecMeasurementValueSize;
            DMTFSpecMeasurementValue = idx_ptr;
            idx_ptr += DMTFSpecMeasurementValueSize;

            if ((size_t) (idx_ptr - data) != data_len) {
                W_ERROR("Something went wrong during parsing the DMTF measurement.\n")
                W_ERROR("Expected length: %i, Actual length: %i\n", (int) data_len, (int) (idx_ptr - data));
                // return false;
            }

            return true;
        
        }
};

class MeasurementRecord {
    private:
        struct _FieldSize {
            int Index = 1;
            int MeasurementSpecification = 1;
            int MeasurementSize = 2;
        } FieldSize;
        int MeasurementSpecification;

        int NumberOfBlocks;
        
        int DMTF_MEASUREMENT_SPECIFICATION_VALUE = 1;
        std::vector<char *> _measurements_list;
    public:
        std::unordered_map<int, DmtfMeasurement> MeasurementBlocks;

        std::unordered_map<int, char*> get_measurements() {
            std::unordered_map<int, char*> measurements;
            for (auto const& [index, measurement] : MeasurementBlocks) {
                // printf("%i ", index);
                char *hex_measurement = to_hex(measurement.DMTFSpecMeasurementValue, measurement.DMTFSpecMeasurementValueSize);
                measurements.insert({index - 1, hex_measurement});
            }
            return measurements;
        }

        void free_measurements() {
            for (char *measurement : _measurements_list) {
                free(measurement);
            }
        }

        MeasurementRecord() = default;
        MeasurementRecord(unsigned char *data, size_t data_len, int number_of_blocks, HopperSettings &settings) {
            NumberOfBlocks = number_of_blocks;
            parse(data, data_len, settings);
        }

        bool parse(unsigned char *data, size_t data_len, HopperSettings &settings) {
            if (NumberOfBlocks == 0) {
                W_ERROR("The number of blocks in the measurement record is zero.\n")
                return false;
            }

            unsigned char *idx_ptr = data;
            for (int _ = 0; _ < NumberOfBlocks; _++) {
                int index = (int) *idx_ptr;
                idx_ptr += FieldSize.Index;
                MeasurementSpecification = (int) *idx_ptr;
                if (MeasurementSpecification != DMTF_MEASUREMENT_SPECIFICATION_VALUE) {
                    W_ERROR("Measurement block not following DMTF specification.\n\tQuitting now.\n")
                    return false;
                }
                idx_ptr += FieldSize.MeasurementSpecification;

                int MeasurementSize = from_little_endian(idx_ptr, FieldSize.MeasurementSize);
                idx_ptr += FieldSize.MeasurementSize;
                MeasurementBlocks.insert({index, DmtfMeasurement(idx_ptr, MeasurementSize)});
                idx_ptr += MeasurementSize;
            }

            if ((size_t) (idx_ptr - data) != data_len) {
                W_ERROR("Something went wrong during parsing the measurement record.\n")
                return false;
            }

            int count = 0;
            for (int i = 1; i <= NumberOfBlocks; i++) {
                if (MeasurementBlocks.find(i) != MeasurementBlocks.end()) {
                    count++;
                }
            }

            if (count == NumberOfBlocks) {
                settings.attestation_report_measurements_availability = true;
            }

            return true;
        }
};


typedef struct _OpaqueField {
    const unsigned char *field_data;
    int field_size;
} OpaqueField;

class OpaqueData {
    private:
        std::unordered_map<int, const char*> OPAQUE_DATA_TYPES = {
            {1   , "OPAQUE_FIELD_ID_CERT_ISSUER_NAME"},
            {2   , "OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER"},
            {3   , "OPAQUE_FIELD_ID_DRIVER_VERSION"},
            {4   , "OPAQUE_FIELD_ID_GPU_INFO"},
            {5   , "OPAQUE_FIELD_ID_SKU"},
            {6   , "OPAQUE_FIELD_ID_VBIOS_VERSION"},
            {7   , "OPAQUE_FIELD_ID_MANUFACTURER_ID"},
            {8   , "OPAQUE_FIELD_ID_TAMPER_DETECTION"},
            {9   , "OPAQUE_FIELD_ID_SMC"},
            {10  , "OPAQUE_FIELD_ID_VPR"},
            {11  , "OPAQUE_FIELD_ID_NVDEC0_STATUS"},
            {12  , "OPAQUE_FIELD_ID_MSRSCNT"},
            {13  , "OPAQUE_FIELD_ID_CPRINFO"},
            {14  , "OPAQUE_FIELD_ID_BOARD_ID"},
            {15  , "OPAQUE_FIELD_ID_CHIP_SKU"},
            {16  , "OPAQUE_FIELD_ID_CHIP_SKU_MOD"},
            {17  , "OPAQUE_FIELD_ID_PROJECT"},
            {18  , "OPAQUE_FIELD_ID_PROJECT_SKU"},
            {19  , "OPAQUE_FIELD_ID_PROJECT_SKU_MOD"},
            {20  , "OPAQUE_FIELD_ID_FWID"},
            {21  , "OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS"},
            {255 , "OPAQUE_FIELD_ID_INVALID"}
        };

        struct _FieldSize {
            int DataType = 2;
            int DataSize = 2;
        } FieldSize;

        int MSR_COUNT_SIZE = 4;

        std::unordered_map<const char*, OpaqueField> OpaqueFields;
        std::vector<int> OpaqueFieldIdMsrCnt;

    public:
        OpaqueField get_field(const char *field_id) {
            if (!strcmp(field_id, "OPAQUE_FIELD_ID_FWID") && OpaqueFields.find(field_id) == OpaqueFields.end()) {
                unsigned char empty[1] = {0};
                return {empty, 0};
            }
            return OpaqueFields[field_id];
        }

        std::vector<int> get_msr_counts() {
            return OpaqueFieldIdMsrCnt;
        }

        OpaqueData() = default;

        OpaqueData(const unsigned char *data, size_t data_len) {
            parse(data, data_len);
        }

        bool parse(const unsigned char *data, size_t data_len) {
            const unsigned char *idx_ptr = data;
            while ((size_t) (idx_ptr - data) < data_len) {
                int data_type_idx = from_little_endian(idx_ptr, FieldSize.DataType);
                const char *data_type = OPAQUE_DATA_TYPES[data_type_idx];
                idx_ptr += FieldSize.DataType;

                int data_size = from_little_endian(idx_ptr, FieldSize.DataSize);
                idx_ptr += FieldSize.DataSize;

                if (!strcmp(data_type, "OPAQUE_FIELD_ID_MSRSCNT")) {
                    parse_measurement_count(idx_ptr, data_size);
                } else {
                    // Consolidate this into one line
                    OpaqueFields.insert({data_type, {idx_ptr, data_size}});
                }
                idx_ptr += data_size;
            }

            if ((size_t) (idx_ptr - data) != data_len) {
                W_ERROR("Something went wrong during parsing the opaque data.\n")
                return false;
            }

            return true;
        }

        bool parse_measurement_count(const unsigned char *data, size_t data_len) {
            if (data_len % MSR_COUNT_SIZE != 0) {
                W_ERROR("The length of the MSR count field is not a multiple of 4.\n")
                return false;
            }
            int num_elements = data_len / MSR_COUNT_SIZE;
            std::vector<int> msr_counts;

            for (int i = 0; i < num_elements; i++) {
                msr_counts.push_back(from_little_endian(data + i * MSR_COUNT_SIZE, MSR_COUNT_SIZE));
            }
            OpaqueFieldIdMsrCnt = msr_counts;
            
            return true;
        }
};

class SpdmMeasurementRequestMessage {
    private:
        struct _FieldSize {
            int SPDMVersion         = 1;
            int RequestResponseCode = 1;
            int Param1              = 1;
            int Param2              = 1;
            int Nonce               = 32;
            int SlotIDParam         = 1;
        } FieldSize;
        unsigned char *SPDMVersion;
        unsigned char *RequestResponseCode;
        unsigned char *Param1;
        unsigned char *Param2;
        unsigned char *Nonce;
        unsigned char *SlotIDParam;
    public:
        SpdmMeasurementRequestMessage() = default;

        SpdmMeasurementRequestMessage(unsigned char *request_data, size_t len) {
            parse(request_data, len);
        }

        bool parse(unsigned char *request_data, size_t len) {
            unsigned char *idx_ptr = request_data;
            SPDMVersion = idx_ptr;
            idx_ptr += FieldSize.SPDMVersion;
            RequestResponseCode = idx_ptr;
            idx_ptr += FieldSize.RequestResponseCode;
            Param1 = idx_ptr;
            idx_ptr += FieldSize.Param1;
            Param2 = idx_ptr;
            idx_ptr += FieldSize.Param2;
            Nonce = idx_ptr;
            idx_ptr += FieldSize.Nonce;
            SlotIDParam = idx_ptr;
            idx_ptr += FieldSize.SlotIDParam;

            if ((size_t) (idx_ptr - request_data) != len) {
                W_ERROR("Something went wrong during parsing the SPDM GET MEASUREMENT request message.\n")
                W_ERROR("Expected length: %i, Actual length: %i\n", (int) len, (int) (idx_ptr - request_data));
                return false;
            }

            return true;
        }
};

class SpdmMeasurementResponseMessage {
    private:
        struct _FieldSize {
            int SPDMVersion             = 1;
            int RequestResponseCode     = 1;
            int Param1                  = 1;
            int Param2                  = 1;
            int NumberOfBlocks          = 1;
            int MeasurementRecordLength = 3;
            int Nonce                   = 32;
            int OpaqueLength            = 2;
        } FieldSize;

    public:
        unsigned char *SPDMVersion;
        unsigned char *RequestResponseCode;
        unsigned char *Param1;
        unsigned char *Param2;
        int NumberOfBlocks;
        int MeasurementRecordLength;
        unsigned char *Nonce;
        int OpaqueLength;
        unsigned char *Signature;
        int SignatureLength;

        MeasurementRecord measurement_record;
        OpaqueData opaque_data;

        SpdmMeasurementResponseMessage() = default;

        SpdmMeasurementResponseMessage(unsigned char *response_data, size_t len, HopperSettings &settings) {
            parse(response_data, len, settings);
        }

        bool parse(unsigned char *response_data, size_t len, HopperSettings &settings) {
            unsigned char *idx_ptr = response_data;
            SPDMVersion = idx_ptr;
            idx_ptr += FieldSize.SPDMVersion;
            RequestResponseCode = idx_ptr;
            idx_ptr += FieldSize.RequestResponseCode;
            Param1 = idx_ptr;
            idx_ptr += FieldSize.Param1;
            Param2 = idx_ptr;
            idx_ptr += FieldSize.Param2;
            // NumberOfBlocks is one byte
            NumberOfBlocks = (int) *idx_ptr;
            idx_ptr += FieldSize.NumberOfBlocks;
            // MeasurementRecordLength is 3 bytes in little endian
            MeasurementRecordLength = from_little_endian(idx_ptr, FieldSize.MeasurementRecordLength);
            // printf("Measurement record length: %i\n", MeasurementRecordLength);
            idx_ptr += FieldSize.MeasurementRecordLength;
            measurement_record = MeasurementRecord(idx_ptr, MeasurementRecordLength, NumberOfBlocks, settings);
            idx_ptr += MeasurementRecordLength;
            Nonce = idx_ptr;
            idx_ptr += FieldSize.Nonce;
            OpaqueLength = from_little_endian(idx_ptr, FieldSize.OpaqueLength);
            idx_ptr += FieldSize.OpaqueLength;

            opaque_data = OpaqueData(idx_ptr, OpaqueLength);
            idx_ptr += OpaqueLength;

            Signature = idx_ptr;
            SignatureLength = settings.signature_length;
            idx_ptr += SignatureLength;

            if ((size_t) (idx_ptr - response_data) != len) {
                W_ERROR("Something went wrong during parsing the SPDM GET MEASUREMENT response message.\n")
                return false;
            }

            return true;
        }

};

class AttestationReport {
    private:
        size_t LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE = 37;
        unsigned char *request_data;
        unsigned char *response_data;
        size_t response_len;
    public:
        bool valid = false;
        SpdmMeasurementRequestMessage request_message;
        SpdmMeasurementResponseMessage response_message;

        AttestationReport(unsigned char *data, size_t data_len, HopperSettings &settings) {
            // std::cout << data_len << std::endl;
            printf("Data length: %i\n", (int) data_len);
            if (data_len <= LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE) {
                W_ERROR("Invalid request message length.\n");
                return;
            }

            request_data = extract_request_message(data);
            response_data = extract_response_message(data);
            request_message = SpdmMeasurementRequestMessage(request_data, LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE);
            response_len = data_len - LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE;
            response_message = SpdmMeasurementResponseMessage(response_data, response_len, settings);
            valid = true;
        }

        unsigned char *extract_response_message(unsigned char *attestation_report_data) {
            return attestation_report_data + LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE;
        }

        unsigned char *extract_request_message(unsigned char *attestation_report_data) {
            return attestation_report_data;
        }

        bool concatenate(unsigned char *request_data, size_t request_len, unsigned char *response_data, size_t response_len, size_t signature_length, /* output */ unsigned char **data) {
            // TODO request length check??
            if (response_len <= signature_length) {
                W_ERROR("The length of the SPDM GET_MEASUREMENT response message is less than \
                         or equal to the length of the signature field, which is not correct.\n");
                return false;
            }
            *data = (unsigned char *) malloc(request_len + response_len - signature_length);
            if (*data == NULL) {
                W_ERROR("Failed to allocate memory for the concatenated message.\n");
                return false;
            }
            memcpy(*data, request_data, request_len);
            memcpy(*data + request_len, response_data, response_len - signature_length);
            return true;
        }

        bool verify_signature(X509 *certificate, size_t signature_length /*, ret_type (*hashfunc)() */) {
                unsigned char *data_whose_signature_is_to_be_verified;
                concatenate(request_data, LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE, response_data, response_len, signature_length, &data_whose_signature_is_to_be_verified);
                int data_length = LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE + response_len - signature_length;
                const unsigned char *signature = response_message.Signature;
                unsigned char hash[SHA384_DIGEST_LENGTH];
                SHA384(data_whose_signature_is_to_be_verified, data_length, hash);

                // EVP_PKEY *pubkey = X509_get_pubkey(certificate);
                // EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pubkey);

                ECDSA_SIG *sig = ECDSA_SIG_new();
                BIGNUM *r = BN_bin2bn(signature, signature_length / 2, NULL);
                BIGNUM *s = BN_bin2bn(signature + signature_length / 2, signature_length / 2, NULL);
                ECDSA_SIG_set0(sig, r, s);

                EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(X509_get_pubkey(certificate));

                int ret = ECDSA_do_verify(hash, SHA384_DIGEST_LENGTH, sig, eckey);
                ECDSA_SIG_free(sig);
                EC_KEY_free(eckey);
                free(data_whose_signature_is_to_be_verified);
                // std::cout << ret << std::endl;
                return ret == 1;


// int ret;
//   ECDSA_SIG *sig;
//   EC_KEY *eckey;
//   eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//   EC_KEY_generate_key(eckey);
//   sig = ECDSA_SIG_new();
//   if (eckey == NULL)
//     printf("err1");
//   unsigned char dgst[] = "test";
//   unsigned char res[32];
//   SHA256(dgst, 32, res);
//   for (int i = 0; i < 32; i++)
//   {
//     printf("%02x", res[i]);
//   }
//   sig = ECDSA_do_sign(res, 32, eckey);
//   if (sig == NULL)
//     printf("err\n");
//   printf("\n");
//   ret = ECDSA_do_verify(res, 32, sig, eckey);
//   printf("%d\n", ret);

                // FILE *fp = fopen("data.bin", "wb");
                // fwrite(data_whose_signature_is_to_be_verified, 1, data_length, fp);
                // fclose(fp);
                // fp = fopen("signature.bin", "wb");
                // fwrite(signature, 1, signature_length, fp);
                // fclose(fp);
                // fp = fopen("hash.bin", "wb");
                // fwrite(hash, 1, SHA384_DIGEST_LENGTH, fp);
                // fclose(fp);

                // std::string plaintext;
                // std::cout << std::endl;
                // ERR_print_errors_fp(stdout);
                // std::cout << std::endl;

                // EVP_PKEY *pubkey = X509_get_pubkey(certificate);
                // EVP_PKEY_CTX *pkeyctx = EVP_PKEY_CTX_new(pubkey, NULL);
                // std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;

                // if (EVP_PKEY_check(pkeyctx) != 1) {
                //     std::cerr << "Failed to check key." << std::endl;
                //     return false;
                // }
                // read pubkey from .crt
                // pubkey = PEM_read_PUBKEY(fopen("test_keys/publickey.crt", "r"), NULL, NULL, NULL);

                // // Create EVP context
                // if (!ctx) {
                //     std::cerr << "Error creating context" << std::endl;
                // }

                // // Initialize decryption operation
                // if (EVP_PKEY_decrypt_init(ctx) != 1) {
                //     std::cerr << "Error initializing decryption" << std::endl;
                //     EVP_PKEY_CTX_free(ctx);
                //     std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
                //     exit(1);
                // }

                // // Provide the ciphertext for decryption
                // if (EVP_PKEY_decrypt(ctx, NULL, NULL, hash, SHA384_DIGEST_LENGTH) <= 0) {
                //     std::cerr << "Error performing decryption" << std::endl;
                //     EVP_PKEY_CTX_free(ctx);
                // }

                // // Get the output length
                // size_t plaintext_len = 0;
                // if (EVP_PKEY_decrypt(ctx, NULL, &plaintext_len, hash, SHA384_DIGEST_LENGTH) <= 0) {
                //     std::cerr << "Error determining output length" << std::endl;
                //     EVP_PKEY_CTX_free(ctx);
                // }

                // plaintext.resize(plaintext_len);

                // // Perform decryption
                // if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &plaintext_len, hash, SHA384_DIGEST_LENGTH) <= 0) {
                //     std::cerr << "Error performing decryption" << std::endl;
                //     EVP_PKEY_CTX_free(ctx);
                // }

                // // Cleanup
                // EVP_PKEY_CTX_free(ctx);

                // return false;



            // EVP_PKEY *public_key = pubkey;
            // X509_print_fp(stdout, certificate);
            // EVP_PKEY *public_key = X509_get_pubkey(certificate);
            // Read public key from file
            // EVP_PKEY *public_key = PEM_read_PUBKEY(fopen("pubkey.pem", "r"), NULL, NULL, NULL);
            // printf("before\n");
            // std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;
            // EVP_PKEY *public_key = PEM_read_PUBKEY(fopen("pubkey.pem", "r"), NULL, NULL, NULL);
            // // EVP_PKEY *public_key = X509_read_PUBKEY(fopen("certs/gpu_cert_chain0.pem", "r"), NULL, NULL, NULL);
            // // EVP_PKEY *public_key = PEM_read_PUBKEY(fopen("test_keys/publickey.crt", "r"), NULL, NULL, NULL);
            // printf("after0\n");
            //     std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;
            // X509* x509 = X509_new();
            // if (!X509_set_pubkey(x509, public_key)) {
            //     std::cerr << "Error setting public key in X509 structure" << std::endl;
            //     X509_free(x509);
            //     return false;
            // }
            // PEM_write_bio_X509(BIO_new_fp(stdout, BIO_NOCLOSE), x509);

            //     std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;

            //     printf("after\n");

            // EVP_PKEY_print_public(BIO_new_fp(stdout, BIO_NOCLOSE), public_key, 0, NULL);

            // std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;

            // // EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(public_key);
            // EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            // EVP_MD_CTX_init(ctx);

            // std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;

            // if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha384(), NULL, public_key) != 1) {
            //     std::cerr << "Failed to initialize verification." << std::endl;
            //     EVP_MD_CTX_free(ctx);
            //     EVP_PKEY_free(public_key);
            //     return false;
            // }

            // std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;


            // if (EVP_DigestVerifyUpdate(ctx, data_whose_signature_is_to_be_verified, data_length) != 1) {
            //     std::cerr << "Failed to update verification." << std::endl;
            //     EVP_MD_CTX_free(ctx);
            //     EVP_PKEY_free(public_key);
            //     return false;
            // }
 
            //     std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;

            // int result = EVP_DigestVerifyFinal(ctx, signature, signature_length);
            // printf("%i, %i\n", (int) hash[0], (int) hash[SHA384_DIGEST_LENGTH - 1]);
            //     std::cout << std::endl;
            //     ERR_print_errors_fp(stdout);
            //     std::cout << std::endl;
            // // std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            // EVP_MD_CTX_free(ctx);
            // EVP_PKEY_free(public_key);
            // if (result != 1) {
            //     std::cerr << "Signature verification failed." << std::endl;
            //     return false;
            // }

            // return true;






            // EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
            // EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(public_key, NULL);
            // if (!md_ctx || !pctx) {
            //     W_ERROR("Error creating message digest context");
            //     EVP_PKEY_free(public_key);
            //     return false;
            // }
            // // EVP_MD_CTX_init(md_ctx);
            // // TODO hash function?
            // if (EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sha384(), NULL, public_key) != 1) {
            //     W_ERROR("Error initializing signature verification");
            //     EVP_MD_CTX_free(md_ctx);
            //     EVP_PKEY_free(public_key);
            //     return false;
            // }

            // unsigned char *data_whose_signature_is_to_be_verified;
            // if (!concatenate(request_data, LENGTH_OF_SPDM_GET_MEASUREMENT_REQUEST_MESSAGE, response_data, response_len, signature_length, &data_whose_signature_is_to_be_verified)) {
            //     W_ERROR("Error concatenating the request and response messages");
            //     EVP_MD_CTX_free(md_ctx);
            //     EVP_PKEY_free(public_key);
            //     return false;
            // }
            // if (EVP_DigestVerifyUpdate(md_ctx, data_whose_signature_is_to_be_verified, data_length) != 1) {
            //     W_ERROR("Error updating signature verification");
            //     free(data_whose_signature_is_to_be_verified);
            //     EVP_MD_CTX_free(md_ctx);
            //     EVP_PKEY_free(public_key);
            //     return false;
            // }
            // // SIGNATURE MISMATCH STARTING ON SIGNATURE[80]
            // int status = EVP_DigestVerifyFinal(md_ctx, signature, signature_length);
            // free(data_whose_signature_is_to_be_verified);
            // std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            // EVP_PKEY_free(public_key);


            // return status == 1;
        }

        std::unordered_map<int, char *> get_measurements() {
            std::unordered_map<int, char *> measurement_list = response_message.measurement_record.get_measurements();

            // TODO error checking?
            return measurement_list;
        }

        void free_measurements() {
            response_message.measurement_record.free_measurements();
        }
};

enum RIM_NAME {
    DRIVER,
    VBIOS
};

class GoldenMeasurement {
    public:
        RIM_NAME name;
        std::vector<char *> measurement_values;
        char *component;
        int index;
        int size;
        int num_alternatives;
        bool active;

        GoldenMeasurement(RIM_NAME rim_name, const std::vector<char *> &measurement_values, char *name, int index, int size, int num_alternatives, bool active) : name(rim_name), measurement_values(measurement_values), component(name), index(index), size(size), num_alternatives(num_alternatives), active(active) {}

};

class RIM {
public:

    const char *DRIVER_RIM_PATH = "rims/NV_GPU_DRIVER_GH100_550.54.15.xml";
    const char *VBIOS_RIM_PATH = "rims/NV_GPU_VBIOS_1010_0210_886_9600740011.xml";

    RIM_NAME rim_name;
    char *file_content;
    rapidxml::xml_document<char> *rim_xml;
    rapidxml::xml_node<char> *root;
    char *colloquial_version;
    std::unordered_map<int, GoldenMeasurement> measurement_map;

    ~RIM() {
        free(file_content);
        // TODO
        delete rim_xml;
    }

    RIM(RIM_NAME name, HopperSettings &settings) : rim_name(name) {
        const char *path = name == DRIVER ? DRIVER_RIM_PATH : VBIOS_RIM_PATH;
        size_t len;
        unsigned char *ufile_content = read_file(path, &len);
        file_content = convert_unsigned_char_star(ufile_content, len);
        free(ufile_content);
        rim_xml = read(file_content);
        if (name == DRIVER) {
            settings.fetch_driver_rim = true;
        } else if (name == VBIOS) {
            settings.fetch_vbios_rim = true;
        }

        colloquial_version = get_colloquial_version();
        parse_measurements(settings);
    }

    rapidxml::xml_document<char> *read(char *content) {
        // TODO
        rapidxml::xml_document<char> *doc = new rapidxml::xml_document<char>();
        try {
            doc->parse<0>(content);
            // printf("%i\n", doc->value_size());
        } catch (rapidxml::parse_error &e) {
            W_ERROR("Error parsing the RIM XML content: %s\n", e.what());
        }
        root = doc->first_node();
        return doc;
    }

    char *get_colloquial_version() {
        rapidxml::xml_node<char> *meta_node = root->first_node("ns0:Meta");
        if (meta_node == NULL) {
            W_ERROR("No Meta element found in the RIM.\n");
            return NULL;
        }

        rapidxml::xml_attribute<char> *version = meta_node->last_attribute("colloquialVersion");
        if (version == NULL) {
            W_ERROR("Driver version not found in the RIM.\n");
            return NULL;
        }
        char *version_string = version->value();
        for (int i = 0; version_string[i]; i++){
            version_string[i] = tolower((unsigned char) version_string[i]);
        }

        return version_string;
    }

    void parse_measurements(HopperSettings &settings) {
        rapidxml::xml_node<char> *payload = root->first_node("ns0:Payload");
        if (payload == NULL) {
            W_ERROR("No Payload element found in the RIM.\n");
            return;
        }

        for (rapidxml::xml_node<char> *child = payload->first_node(); child; child = child->next_sibling()) {
            char *active_str = child->first_attribute("active")->value();
            bool active = !strcmp(active_str, "False") ? false : true;

            int index = atoi(child->first_attribute("index")->value());
            int alternatives = atoi(child->first_attribute("alternatives")->value());
            
            std::vector<char *> measurement_values;
            
            // std::string hash_attr_base = "ns2:Hash";
            const char *hash_attr_base = "ns2:Hash";
            for (int i = 0; i < alternatives; i++) {
                // std::string hash_attr = hash_attr_base + std::to_string(i);
                char *hash_attr = (char *) malloc(strlen(hash_attr_base) + (i / 10) + 2);
                sprintf(hash_attr, "%s%i", hash_attr_base, i);
                // measurement_values.push_back(child->first_attribute(hash_attr.c_str())->value());
                measurement_values.push_back(child->first_attribute(hash_attr)->value());
                free(hash_attr);
                // printf("%i:%s\n", index, measurement_values[i]);
            }
            char *child_name = child->name();
            int child_size = atoi(child->first_attribute("size")->value());
            GoldenMeasurement golden_measurement = GoldenMeasurement(rim_name, measurement_values, child_name, index, child_size, alternatives, active);

            if (measurement_map.find(index) != measurement_map.end()) {
                W_ERROR("Multiple measurement are assigned same index in %s rim.\n", rim_name == DRIVER ? "driver" : "vbios")
                return;
            }
            measurement_map.insert({index, golden_measurement});
        }

        if (measurement_map.size() == 0) {
            W_ERROR("No golden measurements found in the %s RIM.\n", rim_name == DRIVER ? "driver" : "vbios")
            return;
        }

        if (rim_name == DRIVER) {
            settings.rim_driver_measurements_availability = true;
        } else if (rim_name == VBIOS) {
            settings.rim_vbios_measurements_availability = true;
        }
    }

    bool verify_signature(HopperSettings &settings) {
        if (rim_name == DRIVER) {
            settings.driver_rim_certificate_extraction = true;
        } else if (rim_name == VBIOS) {
            settings.vbios_rim_certificate_extraction = true;
        }
        // TODO XML signature local_gpu_verifier\src\verifier\rim\__init__.py::249
        return true;
    }

    bool validate_schema(const char *schema_string) {
        // TODO use Xerces-C++ for schema validation
        // local_gpu_verifier\src\verifier\rim\__init__.py::137
        return true;
    }

    std::vector<X509 *> extract_certificates() {
        rapidxml::xml_node<char> *signature_node = root->first_node("ds:Signature");
        std::vector<X509 *> certificates;
        if (signature_node == NULL) {
            W_ERROR("No Signature element found in the RIM.\n");
            return certificates;
        }

        rapidxml::xml_node<char> *KeyInfo = signature_node->first_node("ds:KeyInfo");
        if (KeyInfo == NULL) {
            W_ERROR("No KeyInfo element found in the RIM.\n");
            return certificates;
        }

        rapidxml::xml_node<char> *X509Data = KeyInfo->first_node("ds:X509Data");
        if (X509Data == NULL) {
            W_ERROR("No X509Data element found in the RIM.\n");
            return certificates;
        }

        for (rapidxml::xml_node<char> *child = X509Data->first_node(); child; child = child->next_sibling()) {
            const char *header = "-----BEGIN CERTIFICATE-----\n";
            char *certificate_body = child->value();
            const char *tail = "-----END CERTIFICATE-----\n";
            int certificate_size = strlen(header) + strlen(certificate_body) + strlen(tail);
            char *certificate_string = (char *) malloc(certificate_size + 1);
            strcpy(certificate_string, header);
            strcat(certificate_string, certificate_body);
            strcat(certificate_string, tail);
            certificate_string[certificate_size] = '\0';
            BIO* certBio = BIO_new_mem_buf((void *) certificate_string, -1);
            X509 *certificate = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
            certificates.push_back(certificate);
            BIO_free(certBio);
            free(certificate_string);
        }

        return certificates;
    }

    bool verify(const char *version, RIM_NAME name, HopperSettings &settings) {
        size_t len;
        unsigned char *uschema_string = read_file("schemas/swidSchema2015.xsd", &len);
        char *schema_string = convert_unsigned_char_star(uschema_string, len);
        free(uschema_string);
        bool schema_valid = validate_schema(schema_string);
        free(schema_string);
        if (!schema_valid) {
            W_ERROR("The RIM does not conform to the SWID schema.\n");
            return false;
        }

        if (name == RIM_NAME::DRIVER) {
            settings.driver_rim_schema_validation = true;
        } else if (name == RIM_NAME::VBIOS) {
            settings.vbios_rim_schema_validation = true;
        }

        if (strcmp(version, colloquial_version)) {
            const char *rim_name = name == DRIVER ? "driver" : "vbios";
            W_ERROR("The %s version in the RIM file is not matching with the installed %s version.\n", rim_name, rim_name);
            return false;
        }
        if (name == RIM_NAME::DRIVER) {
            settings.attestation_report_driver_version_match = true;
        } else if (name == RIM_NAME::VBIOS) {
            settings.attestation_report_vbios_version_match = true;
        }

        std::vector<X509 *> rim_cert_chain = extract_certificates();

        STACK_OF(X509) *cert_chain = sk_X509_new_null();
        for (X509 *certificate : rim_cert_chain) {
            sk_X509_push(cert_chain, certificate);
        }
        unsigned char *uroot_certificate_string = read_file(settings.RIM_ROOT_CERT, &len);
        char *root_certificate_string = convert_unsigned_char_star(uroot_certificate_string, len);
        free(uroot_certificate_string);
        BIO* certBio = BIO_new_mem_buf((void *) root_certificate_string, -1);
        X509 *root_certificate = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
        BIO_free(certBio);
        free(root_certificate_string);
        sk_X509_push(cert_chain, root_certificate);

        HopperSettings::CERT_CHAIN_VERIFICATION_MODE mode = name == DRIVER ? HopperSettings::CERT_CHAIN_VERIFICATION_MODE::DRIVER_RIM_CERT : HopperSettings::CERT_CHAIN_VERIFICATION_MODE::VBIOS_RIM_CERT;
        bool cert_chain_status = verify_certificate_chain(cert_chain, settings, mode);
        if (!cert_chain_status) {
            W_ERROR("%s RIM cert chain verification failed\n", name == DRIVER ? "driver" : "vbios");
            return false;
        }

        // TODO ocsp validation
        // d2i_OCSP_RESPONSE_bio
        // OCSP_response_get1_basic
        // OCSP_basic_verify

        return verify_signature(settings);
    }
};

class Verifier {
public:
    bool is_msr_35_valid = true;
    std::unordered_map<int, GoldenMeasurement> golden_measurements;
    std::unordered_map<int, char*> runtime_measurements;

    Verifier(AttestationReport &attestation_report, RIM &driver_rim, RIM &vbios_rim, HopperSettings &settings) {
        OpaqueField nvdec_status = attestation_report.response_message.opaque_data.get_field("OPAQUE_FIELD_ID_NVDEC0_STATUS");

        // TODO better way to compare?
        if (nvdec_status.field_size != 1) {
            W_ERROR("The NVDEC0 status field size is not 1 byte.\n");
        }
        int nvdec_status_byte = (int) nvdec_status.field_data[0];
        if (nvdec_status_byte == HopperSettings::NVDEC_STATUS::DISABLED) {
            W_ERROR("MSR 35 is invalid.\n");
            is_msr_35_valid = false;
        }

        generate_golden_measurement_list(driver_rim.measurement_map, vbios_rim.measurement_map, settings);
        runtime_measurements = attestation_report.get_measurements();

        attestation_report.free_measurements();
    }

    void generate_golden_measurement_list(std::unordered_map<int, GoldenMeasurement> &driver_measurements, std::unordered_map<int, GoldenMeasurement> &vbios_measurements, HopperSettings &settings) {
        for (auto const& [index, driver_measurement] : driver_measurements) {
            if (driver_measurement.active) {
                golden_measurements.insert({index, driver_measurement});
            }
        }

        for (auto const& [index, vbios_measurement] : vbios_measurements) {
            if (vbios_measurement.active) {
                if (golden_measurements.find(index) != golden_measurements.end()) {
                    W_ERROR("Multiple golden measurements are assigned the same index: %i\n", index)
                }
                golden_measurements.insert({index, vbios_measurement});
            }
        }

        settings.no_driver_vbios_measurement_index_conflict = true;
    }

    bool verify(HopperSettings &settings) {
        if (golden_measurements.size() > runtime_measurements.size()) {
            W_ERROR("The number of golden measurements is greater than the number of runtime measurements.\n");
            return false;
        }

        // for (auto const& [measurement_index, runtime_measurement] : runtime_measurements) {
        //     std::cout << "Index: " << measurement_index << "    " << "Measurement: " << runtime_measurement << std::endl;
        // }
        // std::cout << std::endl << std::endl;
        // for (auto const& [measurement_index, golden_measurements] : golden_measurements) {
        //     std::cout << "Index: " << measurement_index << "    " << "Measurement: " << golden_measurements.measurement_values[0] << std::endl;
        // }

        std::vector<int> mismatched_indices;
        for (auto const& [measurement_index, golden_measurement] : golden_measurements) {
            if (measurement_index == 35 && !is_msr_35_valid)
                continue;
                
            bool is_matching = false;
            for (int alternative_index = 0; alternative_index < golden_measurement.num_alternatives; alternative_index++) {
                char *golden_measurement_value = golden_measurement.measurement_values[alternative_index];
                // printf("%p:%s\n", golden_measurement_value, golden_measurement_value);
                char *runtime_measurement_value = runtime_measurements[measurement_index];
                if (!strcmp(golden_measurement_value, runtime_measurement_value) && golden_measurement.size == (int) strlen(runtime_measurements[measurement_index]) / 2) {
                    is_matching = true;
                    break;
                } else {
                    W_ERROR("Index: %i, Alternative: %i\n", measurement_index, alternative_index);
                    W_ERROR("Golden: %s\n", golden_measurement_value);
                    W_ERROR("Runtime: %s\n", runtime_measurement_value);
                }
            }

            if (!is_matching) {
                mismatched_indices.push_back(measurement_index);
            }
        }

        if (mismatched_indices.size() > 0) {
            W_ERROR("The following golden measurements do not match the runtime measurements:\n");
            for (int index : mismatched_indices) {
                W_ERROR("\tIndex: %i\n", index);
            }
            return false;
        }

        settings.measurement_comparison = true;
        return true;
    }
};

unsigned char *read_file(const char *filename, size_t *len) {
    unsigned char *content = NULL;
    size_t size;
    for (size = 0; filename[size] != '\0'; size++);
    W_DEBUG("Reading file: %p:%s, size=%zu\n", filename, filename, size);
    size_t content_size;
    oe_result_t result = host_read_file(filename, size + 1, &content, &content_size);
    if (result != OE_OK || content == NULL)
    {
        fprintf(
            stderr,
            "Call to host_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
    W_DEBUG("File read %p@%zu\n", content, content_size);
    unsigned char *safe_content = (unsigned char *) malloc(content_size + 1);
    memcpy(safe_content, content, content_size);
    safe_content[content_size] = '\0';
    W_DEBUG("Content: ");
    for (int i = 0; i < 5; i++) {
        W_DEBUG("%i ", safe_content[i]);
    }
    W_DEBUG("\n");
    // *len = strlen(content);
    *len = content_size;
    W_DEBUG("Done file_read %p\n", safe_content);
    return safe_content;
    

    // FILE *fp = fopen(filename, "rb");
    // if (!fp) {
    //     W_ERROR("Failed to open file: %s\n", filename);
    // }

    // W_DEBUG("File opened: %p\n", fp);

    // fseek(fp, 0, SEEK_END);
    // long fsize = ftell(fp);
    // fseek(fp, 0, SEEK_SET);

    // W_DEBUG("File size: %li\n", fsize);

    // unsigned char *content = (unsigned char *)malloc(fsize + 1);
    // fread(content, 1, fsize, fp);
    // fclose(fp);
    // content[fsize] = '\0';

    // W_DEBUG("File read\n");

    // if (len != NULL)
    //     *len = fsize;
    // return content;
}

// int main() {
    // unsigned char *content = read_file("rims/NV_GPU_DRIVER_GH100_550.54.15.xml");
    // content = read_file("rims/NV_GPU_VBIOS_1010_0210_886_9600740011.xml");

    // HopperSettings settings;
    // RIM rim(RIM_NAME::DRIVER, settings, content);
    // const unsigned char *version = "550.54.15";
    // rim.verify(version, RIM_NAME::DRIVER, settings);

    // free(content);


    // unsigned char *project = 
// }
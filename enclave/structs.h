// Minimum TODOs for feature parity
// OCSP validation
// XML schema + signature validation (rapidxml -> Xerces)
// Attestation claims

// Pass in nonces + driver/vbios version
// Dynamically select vbios/driver RIM
// Memory safety + leaks + error handling galore
// Refactoring
// Custom settings?


#include <stdio.h>
// #include <openenclave/3rdparty/libcxx/string>
// #include <openenclave/3rdparty/libcxx/unordered_map>
#include <vector>
#include <string>
#include <unordered_map>
// #include <openenclave/3rdparty/libcxx/vector>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/ocsp.h>

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include "helloworld_t.h"

// #include <openenclave/3rdparty/openssl/x509.h>
// #include <openenclave/3rdparty/openssl/pem.h>
// #include <openenclave/3rdparty/openssl/ecdsa.h>
// #include <openssl/evp.h>
// #include <openssl/sha.h>
// #include <openssl/err.h>
// #include <openssl/obj_mac.h>
// #include <stdlib.h>
#include <string.h>

#include "rapidxml/rapidxml.hpp"

#include <iostream>
// #include <fstream>

#define DEBUG 0
#define W_DEBUG(...) if (DEBUG) fprintf(stdout, __VA_ARGS__);
#define W_ERROR(...) fprintf(stderr, __VA_ARGS__);


#define malloc oe_malloc
#define free oe_free

class HopperSettings {
    public:
        size_t signature_length = 96;
        void /* ret_type */ (*hash_function)(); // = sha384
        size_t MAX_CERT_CHAIN_LENGTH = 5;
        // std::string HashFunctionNamespace = "{http://www.w3.org/2001/04/xmlenc#sha384}";
        const char *GpuArch = "HOPPER";
        size_t SIZE_OF_NONCE_IN_BYTES = 32;

        const char *RIM_ROOT_CERT = "certs/verifier_RIM_root.pem";
        const char *DEVICE_ROOT_CERT = "certs/verifier_device_root.pem";

        enum CERT_CHAIN_VERIFICATION_MODE {
            GPU_ATTESTATION,
            OCSP_RESPONSE,
            DRIVER_RIM_CERT,
            VBIOS_RIM_CERT
        };

        enum NVDEC_STATUS {
            ENABLED = 0xAA,
            DISABLED = 0x55
        };

        bool attestation_report_measurements_availability = false;
        bool gpu_cert_chain_verification = false;
        bool gpu_cert_check_complete = false;
        bool nonce_comparison = false;
        bool attestation_report_driver_version_match = false;
        bool attestation_report_vbios_version_match = false;
        bool fetch_driver_rim = false;
        bool fetch_vbios_rim = false;
        bool rim_driver_measurements_availability = false;
        bool rim_vbios_measurements_availability = false;
        bool driver_rim_schema_validation = false;
        bool vbios_rim_schema_validation = false;
        bool driver_rim_certificate_extraction = true;
        bool vbios_rim_certificate_extraction = true;
        bool driver_rim_signature_verification = true;
        bool vbios_rim_signature_verification = true;
        bool no_driver_vbios_measurement_index_conflict = false;
        bool measurement_comparison = false;

        std::unordered_map<const char *, bool> claims;

        void print_status() {
            std::cout << "attestation_report_measurements_availability = " << attestation_report_measurements_availability << std::endl;
            std::cout << "gpu_cert_chain_verification = " << gpu_cert_chain_verification << std::endl;
            std::cout << "gpu_cert_check_complete = " << gpu_cert_check_complete << std::endl;
            std::cout << "nonce_comparison = " << nonce_comparison << std::endl;
            std::cout << "attestation_report_driver_version_match = " << attestation_report_driver_version_match << std::endl;
            std::cout << "attestation_report_vbios_version_match = " << attestation_report_vbios_version_match << std::endl;
            std::cout << "fetch_driver_rim = " << fetch_driver_rim << std::endl;
            std::cout << "fetch_vbios_rim = " << fetch_vbios_rim << std::endl;
            std::cout << "rim_driver_measurements_availability = " << rim_driver_measurements_availability << std::endl;
            std::cout << "rim_vbios_measurements_availability = " << rim_vbios_measurements_availability << std::endl;
            std::cout << "driver_rim_schema_validation = " << driver_rim_schema_validation << std::endl;
            std::cout << "vbios_rim_schema_validation = " << vbios_rim_schema_validation << std::endl;
            std::cout << "driver_rim_certificate_extraction = " << driver_rim_certificate_extraction << std::endl;
            std::cout << "vbios_rim_certificate_extraction = " << vbios_rim_certificate_extraction << std::endl;
            std::cout << "driver_rim_signature_verification = " << driver_rim_signature_verification << std::endl;
            std::cout << "vbios_rim_signature_verification = " << vbios_rim_signature_verification << std::endl;
            std::cout << "no_driver_vbios_measurement_index_conflict = " << no_driver_vbios_measurement_index_conflict << std::endl;
            std::cout << "measurement_comparison = " << measurement_comparison << std::endl;
        }

        bool check_status() {

            // self.claims["x-nv-gpu-available"] = self.check_gpu_availability()
            claims.insert({"x-nv-gpu-attestation-report-available", attestation_report_measurements_availability});
            // self.claims["x-nv-gpu-info-fetched"] = self.check_if_gpu_info_fetched()
            // self.claims["x-nv-gpu-arch-check"] = self.check_if_gpu_arch_is_correct()
            // self.claims["x-nv-gpu-root-cert-available"] = self.get_root_cert_availability()
            claims.insert({"x-nv-gpu-cert-chain-verified", gpu_cert_chain_verification});
            // self.claims["x-nv-gpu-ocsp-cert-chain-verified"] = self.check_if_gpu_certificate_ocsp_cert_chain_verified()
            // self.claims["x-nv-gpu-ocsp-signature-verified"] = self.check_if_gpu_certificate_ocsp_signature_verified()
            // self.claims["x-nv-gpu-cert-ocsp-nonce-match"] = self.check_if_gpu_certificate_ocsp_nonce_match()
            claims.insert({"x-nv-gpu-cert-check-complete", gpu_cert_check_complete});
            // self.claims["x-nv-gpu-measurement-available"] = self.check_attestation_report_measurement_availability()
            // self.claims["x-nv-gpu-attestation-report-parsed"] = self.check_if_attestation_report_parsed_successfully()
            // self.claims["x-nv-gpu-nonce-match"] = self.check_if_nonce_are_matching()
            // self.claims[
            //     "x-nv-gpu-attestation-report-driver-version-match"] = self.check_if_attestation_report_driver_version_matches()
            // self.claims[
            //     "x-nv-gpu-attestation-report-vbios-version-match"] = self.check_if_attestation_report_vbios_version_matches()
            // self.claims["x-nv-gpu-attestation-report-verified"] = self.check_if_attestation_report_verified()
            // self.claims["x-nv-gpu-driver-rim-schema-fetched"] = self.check_if_driver_rim_fetched()
            // self.claims["x-nv-gpu-driver-rim-schema-validated"] = self.check_if_driver_rim_schema_validated()
            // self.claims["x-nv-gpu-driver-rim-cert-extracted"] = self.check_if_driver_rim_cert_extracted()
            // self.claims["x-nv-gpu-driver-rim-signature-verified"] = self.check_if_driver_rim_signature_verified()
            // self.claims["x-nv-gpu-driver-rim-driver-measurements-available"] = self.check_rim_driver_measurements_availability()
            // self.claims["x-nv-gpu-driver-vbios-rim-fetched"] = self.check_if_vbios_rim_fetched()
            // self.claims["x-nv-gpu-vbios-rim-schema-validated"] = self.check_if_vbios_rim_schema_validated()
            // self.claims["x-nv-gpu-vbios-rim-cert-extracted"] = self.check_if_vbios_rim_cert_extracted()
            // self.claims["x-nv-gpu-vbios-rim-signature-verified"] = self.check_if_vbios_rim_signature_verified()
            // self.claims["x-nv-gpu-vbios-rim-driver-measurements-available"] = self.check_rim_vbios_measurements_availability()
            // self.claims["x-nv-gpu-vbios-index-no-conflict"] = self.check_if_no_driver_vbios_measurement_index_conflict()
            // self.claims["x-nv-gpu-measurements-match"] = self.check_if_measurements_are_matching()
            

            return true;
        }
};
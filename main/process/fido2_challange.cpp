//
// Created by Stefan Weber on 15.11.23.
//
#include "../process.h"
#include "../sensitive.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"
#include "../jade_assert.h"
#include "process_utils.h"

void fido2_authenticate(const unsigned char *challenge, size_t challenge_len, uint8_t* sig_output, const size_t sig_len, const uint32_t* path,
    const size_t path_len) {
    // Derive the child key
    int ret;
    uint8_t privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    wallet_get_privkey(path, path_len, privkey, sizeof(privkey));
    // Assuming private_key is already available and securely stored
    unsigned char signature[64];   // Buffer for the signature

    // Sign the challenge using libwally
    ret = wally_ec_sig_from_bytes(privkey, sizeof(privkey),
        challenge, challenge_len,
        EC_FLAG_ECDSA | EC_FLAG_GRIND_R,
        sig_output, sig_len);
    if (ret != WALLY_OK) {
        // Handle error
    }

    // TODO: Format the signature as required by FIDO2

    // Clean up
    wally_cleanup(0);
}


/*
 * The message flow here is complicated because we cater for both a legacy flow
 * for standard deterministic EC signatures (see rfc6979) and a newer message
 * exchange added later to cater for anti-exfil signatures.
 * At the moment we retain the older message flow for backward compatibility,
 * but at some point we could remove it and use the new message flow for all
 * cases, which would simplify the code here and in the client.
 */
void fido2_authenticate_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "fido2_authenticate");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // We accept a signing file, as produced by Specter wallet app (at least)
    if (rpc_has_field_data("challenge", &params)) {
        const char* challenge = NULL;
        size_t challenge_len = 0;
        rpc_get_string_ptr("challenge", &params, &challange, &challange_len);
        if (!challenge || !challenge_len) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid sign message file data", NULL);
            goto cleanup;
        }

        uint8_t signature[EC_SIGNATURE_LEN * 2]; // Sufficient
        size_t written = 0;
        signing_data_t* const sig_data = all_signing_data + index;
        rpc_get_id(&process->ctx.value, sig_data->id, sizeof(sig_data->id), &written);
        JADE_ASSERT(written != 0);
        const char* errmsg = NULL;
        const int errcode
            = fido2_authenticate((const unsigned char*)challenge, challenge_len, signature, sizeof(signature), sig_data->path, sig_data->path_len);
        if (errcode) {
            jade_process_reject_message(process, errcode, errmsg, NULL);
            goto cleanup;
        }

        JADE_ASSERT(written);
        JADE_ASSERT(written < sizeof(signature));
        JADE_ASSERT(signature[written - 1] == '\0');
        // todo add also public key or pubkey can be requested by: get_identity_pubkey

        jade_process_reply_to_message_result(process->ctx, (const char*)signature, cbor_result_string_cb);
        return;
    }

    JADE_LOGI("Success");

cleanup:
    return;
}
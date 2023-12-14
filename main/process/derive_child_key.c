#include "../descriptor.h"
#include "../gui.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/address.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "../button_events.h"

#include <esp_event.h>
#include <wally_script.h>

#include "process_utils.h"

/**
 * @brief This function is used to derive a child key in a hierarchical deterministic (HD) wallet.
 *
 * @param process_ptr A pointer to the process structure. This structure contains all the information
 *                    related to the current process, including the network, keychain, and other parameters.
 *
 * The function first checks if the current message is "derive_child" and if the keychain is unlocked.
 * It then extracts the BIP32 path from the parameters. If the path is not valid, it rejects the message.
 *
 * If the path is not as expected, it shows a warning message with the address. It then tries to get the
 * HD key for the given path. If it fails to generate a valid singlesig script, it rejects the message.
 *
 * If the script variant is not handled, it rejects the message. If the user accepts, it shows a warning
 * if necessary and replies with the address.
 *
 * If any error occurs during the process, it goes to cleanup and returns.
 */
void get_child_key_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    // Explicitly cast the void* to jade_process_t*
     jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "derive_child");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    // Declare variables before the GET_MSG_PARAMS macro
    char warning_msg[128] = {'\0'};
    uint32_t path[MAX_PATH_LEN];
    size_t path_len = 0;
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);
    char variant[MAX_VARIANT_LEN];
    script_variant_t script_variant;
    size_t written = 0;
    struct ext_key derived;

    // Now call the macro
    GET_MSG_PARAMS(process);

if (rpc_has_field_data("derive_child", &params)) {

        	rpc_get_string("variant", sizeof(variant), &params, variant, &written);
        	if (!get_script_variant(variant, written, &script_variant)) {
            	jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid script variant parameter", NULL);
            	goto cleanup;
        	}

            rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);
            if (path_len == 0) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
                 goto cleanup;
            }

            // If paths not as expected show a warning message with the address
            bool is_change = false;
            if (!wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len)) {
                is_change = wallet_is_expected_singlesig_path(network, script_variant, true, path, path_len);

                char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                if (!wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str))) {
                    jade_process_reject_message(
                        process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert path to string format", NULL);
                     goto cleanup;
                }
                const char* path_desc = is_change ? "Note:\nChange path" : "Warning:\nUnusual path";
                const int ret = snprintf(warning_msg, sizeof(warning_msg), "%s\n%s", path_desc, path_str);
                JADE_ASSERT(ret > 0 && ret < sizeof(warning_msg));
            }


            if (!wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PRIVATE, &derived)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid singlesig script", NULL);
                 goto cleanup;
            }
        } else {
            // Multisig handled above, so should be nothing left
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unhandled script variant", NULL);
             goto cleanup;
        }

    JADE_LOGD("User pressed accept");

    // Show warning if necessary
    if (warning_msg[0] != '\0') {
        await_message_activity(warning_msg);
    }

    // Reply with the address
    jade_process_reply_to_message_result(process->ctx, derived.priv_key, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
     return;
}

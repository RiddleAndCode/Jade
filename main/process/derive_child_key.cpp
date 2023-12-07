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

void get_child_key_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "derive_child");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    char warning_msg[128];
    warning_msg[0] = '\0';

    uint32_t path[MAX_PATH_LEN];
    size_t path_len = 0;
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);

    script_variant_t script_variant;

    struct ext_key derived;

if (rpc_has_field_data("derive_child", &params)) {
            rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);
            if (path_len == 0) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
                return;
            }

            // If paths not as expected show a warning message with the address
            bool is_change = false;
            if (!wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len)) {
                is_change = wallet_is_expected_singlesig_path(network, script_variant, true, path, path_len);

                char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                if (!wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str))) {
                    jade_process_reject_message(
                        process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert path to string format", NULL);
                    return;
                }
                const char* path_desc = is_change ? "Note:\nChange path" : "Warning:\nUnusual path";
                const int ret = snprintf(warning_msg, sizeof(warning_msg), "%s\n%s", path_desc, path_str);
                JADE_ASSERT(ret > 0 && ret < sizeof(warning_msg));
            }


            if (!wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PRIVATE, &derived)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid singlesig script", NULL);
                return;
            }
        } else {
            // Multisig handled above, so should be nothing left
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unhandled script variant", NULL);
            return;
        }

    JADE_LOGD("User pressed accept");

    // Show warning if necessary
    if (warning_msg[0] != '\0') {
        await_message_activity(warning_msg);
    }

    // Reply with the address
    jade_process_reply_to_message_result(process->ctx, derived.priv_key, cbor_result_string_cb);

    JADE_LOGI("Success");
}

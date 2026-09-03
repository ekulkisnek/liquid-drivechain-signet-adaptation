#include <bitcoinconsensus.h>

int main(void)
{
    const unsigned char script[] = {0x51};
    const unsigned char amount[9] = {1};
    /* One unsigned Bitcoin-mode input and no outputs; script verification only. */
    unsigned char tx[51] = {1};
    bitcoinconsensus_error error = bitcoinconsensus_ERR_OK;
    tx[4] = 1;

    if (bitcoinconsensus_version() != BITCOINCONSENSUS_API_VER) return 1;
    if (bitcoinconsensus_verify_script(0, script, sizeof(script), tx, 0, 0, 0, &error) ||
        error != bitcoinconsensus_ERR_TX_DESERIALIZE) return 2;
    if (bitcoinconsensus_verify_script(0, script, sizeof(script), tx, sizeof(tx), 0,
        1U << 31, &error) || error != bitcoinconsensus_ERR_INVALID_FLAGS) return 3;
    if (bitcoinconsensus_verify_script(0, script, sizeof(script), tx, sizeof(tx), 0,
        bitcoinconsensus_SCRIPT_FLAGS_VERIFY_WITNESS, &error) ||
        error != bitcoinconsensus_ERR_AMOUNT_REQUIRED) return 4;
    if (!bitcoinconsensus_verify_script(0, script, sizeof(script), tx, sizeof(tx), 0,
        0, &error) || error != bitcoinconsensus_ERR_OK) return 5;
    if (!bitcoinconsensus_verify_script_with_amount(0, script, sizeof(script),
        amount, sizeof(amount), tx, sizeof(tx), 0, 0, &error) ||
        error != bitcoinconsensus_ERR_OK) return 6;
    if (bitcoinconsensus_verify_script(0, script, sizeof(script), tx, sizeof(tx), 1,
        0, &error) || error != bitcoinconsensus_ERR_TX_INDEX) return 7;
    return 0;
}

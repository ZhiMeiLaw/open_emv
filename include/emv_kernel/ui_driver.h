/**
 * @file emv_kernel/ui_driver.h
 * @brief User interface driver — abstracts PIN prompt and display.
 *
 * Optional interface. If a kernel doesn't need user interaction (e.g.,
 * K5 no-CVM), this driver can be NULL.
 */

#ifndef EMV_KERNEL_UI_DRIVER_H
#define EMV_KERNEL_UI_DRIVER_H

#include <stdint.h>

typedef struct {
    /**
     * Prompt cardholder for PIN and return encrypted PIN block.
     * @param pan              PAN for PIN block format (bytes)
     * @param pan_len          PAN length in bytes
     * @param encrypted_pin    Output buffer for PIN block
     * @param pin_block_len    In/out: max bytes, actual bytes written
     * @param key_index        Key index for PIN encryption (optional)
     * @return 0=success, -1=timeout/cancel, -2=wrong PIN entered
     */
    int (*prompt_pin)(const uint8_t *pan, uint16_t pan_len,
                      uint8_t *encrypted_pin, uint16_t *pin_block_len,
                      uint8_t key_index);

    /**
     * Display a status message to the cardholder.
     * Non-blocking; returns immediately.
     */
    void (*display_message)(const char *msg);

    /**
     * Get transaction amount from user input (optional).
     * Only needed for kernels that support manual entry.
     */
    int (*get_amount_from_user)(uint32_t *amount);

    uint8_t version;
} ui_driver_t;

#endif /* EMV_KERNEL_UI_DRIVER_H */

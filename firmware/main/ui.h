/* Setup and admin web UI. */
#pragma once

#include <stdbool.h>

#include "pt_esp.h"

/**
 * @brief Initialise the UI.
 * @param cfg         live configuration (the UI edits and saves it)
 * @param setup_mode  true when running the setup access point
 */
void ui_init(pt_config_t *cfg, bool setup_mode);

/** @brief HTTP handler for the UI (registered with pt_httpd_set_ui). */
void ui_handle(void *ctx, const pt_srv_request_t *req, pt_srv_response_t *resp, bool on_ap);

/** @brief Seconds since the last configuration change made through the UI (setup timeout). */
uint32_t ui_idle_seconds(void);

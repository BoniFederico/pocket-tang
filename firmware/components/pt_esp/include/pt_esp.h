/**
 * @file pt_esp.h
 * @brief ESP-IDF platform layer of Pocket Tang: persistent storage, Wi-Fi, HTTP server, crypto
 *        worker, statistics and the optional test console.
 *
 * Everything that touches ESP-IDF lives in this component; protocol logic lives in the portable
 * core (pt_core).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "pt/pt_server.h"
#include "pt/pt_tang.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------------------------ */
/* Configuration and persistent storage (NVS)                                                  */
/* ------------------------------------------------------------------------------------------ */

#define PT_SSID_MAX 32
#define PT_PASS_MAX 64
#define PT_HOST_MAX 32

/** Device configuration. Secrets (Wi-Fi password, admin hash) are never logged. */
typedef struct pt_config {
    bool provisioned; /**< Wi-Fi credentials are present */
    char ssid[PT_SSID_MAX + 1];
    char pass[PT_PASS_MAX + 1];
    char hostname[PT_HOST_MAX + 1];
    uint16_t port;  /**< Tang HTTP port */
    bool admin_set; /**< an admin password is configured */
    uint8_t admin_salt[16];
    uint8_t admin_hash[32]; /**< PBKDF2-HMAC-SHA256(password, salt) */
    uint32_t admin_iter;
    bool locked;    /**< /rec kill switch (persisted) */
    bool lan_admin; /**< admin UI reachable in normal mode */
} pt_config_t;

/** @brief Initialise NVS (erasing it only if the partition layout is incompatible). */
esp_err_t pt_store_init(void);
/** @brief Load the configuration; missing values get defaults. */
esp_err_t pt_store_load_config(pt_config_t *cfg);
/** @brief Persist the configuration. */
esp_err_t pt_store_save_config(const pt_config_t *cfg);
/** @brief Load the key-store blob. ESP_ERR_NOT_FOUND if none. */
esp_err_t pt_store_load_keys(uint8_t *blob, size_t cap, size_t *len);
/** @brief Persist the key-store blob. */
esp_err_t pt_store_save_keys(const uint8_t *blob, size_t len);
/** @brief Erase keys, configuration and statistics (factory reset). */
esp_err_t pt_store_factory_reset(void);

/** Length of the setup access-point password. */
#define PT_SETUP_PW_LEN 12

/**
 * @brief Get the per-device WPA2 password of the setup access point, generating and storing a
 *        random one on first use (a factory reset generates a new one).
 * @param out Receives PT_SETUP_PW_LEN characters plus NUL.
 */
esp_err_t pt_store_setup_password(char out[PT_SETUP_PW_LEN + 1]);

/* ------------------------------------------------------------------------------------------ */
/* Status LED and BOOT button                                                                   */
/* ------------------------------------------------------------------------------------------ */

typedef enum pt_led_state {
    PT_LED_OFF = 0,
    PT_LED_CONNECTING, /**< fast blink: joining Wi-Fi */
    PT_LED_NORMAL,     /**< off, short blip on each recovery */
    PT_LED_SETUP,      /**< slow blink (1 Hz): setup mode */
    PT_LED_HOLD_SETUP, /**< very fast blink: release now to enter setup mode */
    PT_LED_HOLD_RESET, /**< solid on: release now to factory reset */
    PT_LED_ERROR,      /**< triple blink: keys unavailable */
} pt_led_state_t;

/** @brief Configure the LED GPIO (CONFIG_PT_LED_GPIO; no-op if < 0). */
void pt_led_init(void);
/** @brief Set the LED pattern. Every change is logged as "PT_LED <name>" for HIL tests. */
void pt_led_set(pt_led_state_t state);
/** @brief Current pattern. */
pt_led_state_t pt_led_get(void);
/** @brief Short blip (successful recovery) without changing the pattern. */
void pt_led_blip(void);

typedef enum pt_button_action {
    PT_BUTTON_SETUP = 1, /**< held 3..10 s: enter setup mode (keys kept) */
    PT_BUTTON_RESET = 2, /**< held >= 10 s: factory reset (keys destroyed) */
} pt_button_action_t;

/** Callback invoked on the button task after the button is released. */
typedef void (*pt_button_cb)(pt_button_action_t action);

/** @brief Start watching the BOOT button (CONFIG_PT_BUTTON_GPIO, active low). */
esp_err_t pt_button_start(pt_button_cb cb);

/** @brief Test builds: simulate holding the button for @p ms milliseconds. */
void pt_button_simulate(uint32_t ms);

/* ------------------------------------------------------------------------------------------ */
/* Crypto worker                                                                                */
/* ------------------------------------------------------------------------------------------ */

/** A unit of work executed on the crypto worker task. */
typedef void (*pt_job_fn)(void *arg);

/** @brief Start the worker task that owns the Tang engine. */
esp_err_t pt_worker_start(void);

/**
 * @brief Run @p fn(@p arg) on the worker and wait for it to finish.
 *
 * Fails immediately with ESP_ERR_TIMEOUT if the queue is full (the caller answers 503); once
 * accepted, the job always runs to completion before this returns, so @p arg may live on the
 * caller's stack.
 */
esp_err_t pt_worker_run(pt_job_fn fn, void *arg);

/** @brief The Tang engine. Only touch it from worker jobs. */
pt_tang_t *pt_engine(void);

/** @brief Save the key store to NVS. Call from a worker job after any key change. */
esp_err_t pt_engine_persist_keys(void);

/* ------------------------------------------------------------------------------------------ */
/* Statistics                                                                                   */
/* ------------------------------------------------------------------------------------------ */

typedef struct pt_stats {
    uint32_t rec_ok;
    uint32_t rec_denied;
    uint32_t adv;
    uint32_t busy;             /**< requests refused with 503 (queue full) */
    int64_t last_unlock_epoch; /**< seconds since epoch (0 if unknown or never) */
    char last_client[48];      /**< IP of the last successful /rec client */
    uint32_t rec_last_us;      /**< crypto time of the last successful /rec */
    uint32_t rec_max_us;
    uint64_t rec_total_us;
    uint32_t worker_stack_free; /**< worker stack high-water mark (bytes still free) */
    uint32_t httpd_stack_free;
    uint32_t heap_free;
    uint32_t heap_min_free;
    uint32_t heap_largest_block;
} pt_stats_t;

/** @brief Snapshot the statistics (thread safe). */
void pt_stats_get(pt_stats_t *out);
/** @brief Record a Tang event (called from the worker). */
void pt_stats_event(pt_tang_event_t ev, int status, const char *client, uint32_t crypto_us);
/** @brief Record a 503. */
void pt_stats_busy(void);
/** @brief Record the HTTP task's stack high-water mark. */
void pt_stats_httpd_stack(uint32_t free_bytes);

/* ------------------------------------------------------------------------------------------ */
/* Network                                                                                      */
/* ------------------------------------------------------------------------------------------ */

/** @brief Bring up Wi-Fi in station mode and keep it connected (with backoff). */
esp_err_t pt_wifi_start_sta(const pt_config_t *cfg);
/** @brief Wait until an IPv4 address is obtained. */
bool pt_wifi_wait_ip(uint32_t timeout_ms);
/** @brief Current IPv4 address as text (empty if none). */
void pt_wifi_ip(char *out, size_t cap);
/** @brief RSSI of the current AP, or 0 when not connected. */
int pt_wifi_rssi(void);
/** @brief Start mDNS advertising <hostname>.local and the Tang HTTP service. */
esp_err_t pt_mdns_start(const char *hostname, uint16_t port);

/** IPv4 address of the setup access point. */
#define PT_AP_IP "192.168.4.1"

/**
 * @brief Start setup mode: a WPA2 access point @p ap_ssid / @p ap_pass, plus the station
 *        connection when @p with_sta is true (so Tang keeps serving while in setup mode).
 */
esp_err_t pt_wifi_start_setup(const pt_config_t *cfg, const char *ap_ssid, const char *ap_pass,
                              bool with_sta);

/** One scanned network. */
typedef struct pt_scan_ap {
    char ssid[PT_SSID_MAX + 1];
    int8_t rssi;
    bool secure;
} pt_scan_ap_t;

/**
 * @brief Scan for networks (blocking, ~2 s). Duplicate SSIDs are merged (strongest kept).
 * @return number of entries written to @p out.
 */
int pt_wifi_scan(pt_scan_ap_t *out, int max);

/** @brief Number of stations connected to the setup access point. */
int pt_wifi_ap_clients(void);

/** @brief Start the captive-portal DNS responder on the access point (UDP port 53). */
esp_err_t pt_dnsd_start(void);

/* ------------------------------------------------------------------------------------------ */
/* HTTP                                                                                         */
/* ------------------------------------------------------------------------------------------ */

/** Handler for the setup/admin UI (implemented by the application). */
typedef void (*pt_ui_handler_fn)(void *ctx, const struct pt_srv_request *req,
                                 struct pt_srv_response *resp, bool on_ap);

/**
 * @brief Start the HTTP server: Tang on @p tang_port, plus @p extra_port (e.g. 80 for the
 *        captive portal) if non-zero and different.
 */
esp_err_t pt_httpd_start(uint16_t tang_port, uint16_t extra_port);

/**
 * @brief Route requests arriving on the access point address @p ap_ip (and /admin on the LAN
 *        when @p lan_admin is true) to @p fn instead of the Tang endpoints.
 */
void pt_httpd_set_ui(pt_ui_handler_fn fn, void *ctx, const char *ap_ip, bool lan_admin);

/* ------------------------------------------------------------------------------------------ */
/* Test console (CONFIG_PT_TEST_CONSOLE only)                                                   */
/* ------------------------------------------------------------------------------------------ */

/** @brief Start the serial test console. No-op unless CONFIG_PT_TEST_CONSOLE is set. */
void pt_console_start(void);

#ifdef __cplusplus
}
#endif

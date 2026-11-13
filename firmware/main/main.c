/*
 * Pocket Tang firmware entry point and mode state machine.
 *
 *   not provisioned ──────────────► SETUP (access point only; first-time setup page)
 *   provisioned ─────────────────► NORMAL (station; Tang on the configured port)
 *   NORMAL + button 3..10 s ─────► restart into SETUP (access point + station: Tang keeps
 *                                   serving on the LAN; admin page on the access point)
 *   SETUP idle for N minutes ────► restart into NORMAL (only when provisioned)
 *   any mode + button >= 10 s ───► factory reset (keys and settings erased) → SETUP
 *
 * The "enter setup mode" request survives the restart in RTC memory, so no flash write is
 * needed for a mode change.
 */
#include <inttypes.h>
#include <string.h>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pt/pt_version.h"
#include "pt_esp.h"
#include "sdkconfig.h"
#include "ui.h"

static const char *TAG = "pocket-tang";

#define SETUP_MAGIC 0x53455455u /* "SETU" */

static RTC_NOINIT_ATTR uint32_t s_boot_request;
static pt_config_t s_cfg;

typedef struct boot_job {
    esp_err_t result;
} boot_job_t;

/* Runs on the worker: load the key store from NVS or create fresh keys. */
static void load_keys_job(void *arg)
{
    boot_job_t *b = arg;
    static uint8_t blob[PT_KEYSTORE_BLOB_MAX];
    size_t len = 0;
    pt_keystore_t *ks = pt_tang_keystore(pt_engine());
    esp_err_t err = pt_store_load_keys(blob, sizeof(blob), &len);
    if (err == ESP_OK) {
        pt_err_t perr = pt_keystore_load(ks, blob, len);
        pt_zeroize(blob, sizeof(blob));
        if (perr != PT_OK) {
            /* Fail closed: never silently replace keys that exist but do not validate. */
            ESP_LOGE(TAG, "stored keys are invalid (%s); refusing to serve", pt_err_str(perr));
            b->result = ESP_ERR_INVALID_STATE;
            return;
        }
    } else if (err == ESP_ERR_NOT_FOUND) {
        ESP_LOGI(TAG, "no keys yet, generating ES512 + ECMR (P-521)");
        if (pt_keystore_ensure(ks) != PT_OK) {
            b->result = ESP_FAIL;
            return;
        }
        err = pt_engine_persist_keys();
        if (err != ESP_OK) {
            b->result = err;
            return;
        }
    } else {
        b->result = err;
        return;
    }
    b->result = pt_tang_refresh(pt_engine()) == PT_OK ? ESP_OK : ESP_FAIL;
}

static void log_thumbprints_job(void *arg)
{
    (void)arg;
    const pt_keystore_t *ks = pt_tang_keystore(pt_engine());
    for (unsigned i = 0; i < pt_keystore_count(ks); i++) {
        const pt_key_t *k = pt_keystore_at(ks, i);
        char thp[PT_THP_MAX];
        if (pt_jwk_thumbprint_b64(&k->pub, PT_HASH_SHA256, thp, sizeof(thp)) == PT_OK) {
            ESP_LOGI(TAG, "key %s %s%s", k->alg == PT_ALG_ES512 ? "ES512" : "ECMR ", thp,
                     k->rotated ? " (rotated)" : "");
        }
    }
}

static void set_lock_job(void *arg)
{
    pt_tang_set_locked(pt_engine(), *(bool *)arg);
}

static void on_button(pt_button_action_t action)
{
    if (action == PT_BUTTON_RESET) {
        ESP_LOGW(TAG, "FACTORY RESET from the BOOT button: erasing keys and settings");
        pt_store_factory_reset();
        s_boot_request = 0;
    } else {
        ESP_LOGW(TAG, "entering setup mode (BOOT button)");
        s_boot_request = SETUP_MAGIC;
    }
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_restart();
}

static void halt_with_error(const char *why)
{
    ESP_LOGE(TAG, "%s", why);
    pt_led_set(PT_LED_ERROR);
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000)); /* the button still works: factory reset recovers */
    }
}

static void start_keys(void)
{
    boot_job_t boot = {0};
    pt_worker_run(load_keys_job, &boot);
    if (boot.result != ESP_OK) {
        halt_with_error("key store unavailable; Tang disabled (factory reset to recover)");
    }
    pt_worker_run(log_thumbprints_job, NULL);
    pt_worker_run(set_lock_job, &s_cfg.locked);
}

static void setup_mode(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    char ssid[24];
    snprintf(ssid, sizeof(ssid), "PocketTang-%02X%02X", mac[4], mac[5]);
    char pw[PT_SETUP_PW_LEN + 1];
    ESP_ERROR_CHECK(pt_store_setup_password(pw));
    pt_led_set(PT_LED_SETUP);
    ESP_ERROR_CHECK(pt_wifi_start_setup(&s_cfg, ssid, pw, s_cfg.provisioned));
    /* Printed on purpose: reading the serial console requires physical access. */
    ESP_LOGW(TAG, "PT_SETUP_AP ssid=%s password=%s url=http://" PT_AP_IP "/admin", ssid, pw);
    pt_zeroize(pw, sizeof(pw));
    start_keys();
    ui_init(&s_cfg, true);
    pt_httpd_set_ui(ui_handle, NULL, PT_AP_IP, s_cfg.lan_admin);
    uint16_t tang_port = s_cfg.provisioned ? s_cfg.port : 80;
    ESP_ERROR_CHECK(pt_httpd_start(tang_port, 80));
    ESP_ERROR_CHECK(pt_dnsd_start());
    if (s_cfg.provisioned && pt_wifi_wait_ip(20000)) {
        pt_mdns_start(s_cfg.hostname, s_cfg.port);
    }
    char ip[16];
    pt_wifi_ip(ip, sizeof(ip));
    ESP_LOGI(TAG, "PT_READY mode=setup ip=%s port=%u", ip, tang_port);
    /* Leave setup mode automatically once provisioned and idle. */
    const uint32_t timeout_s = (uint32_t)CONFIG_PT_SETUP_TIMEOUT_MIN * 60u;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        if (s_cfg.provisioned && timeout_s > 0 && ui_idle_seconds() > timeout_s &&
            pt_wifi_ap_clients() == 0) {
            ESP_LOGI(TAG, "setup mode timeout: restarting in normal mode");
            esp_restart();
        }
    }
}

static void normal_mode(void)
{
    pt_led_set(PT_LED_CONNECTING);
    ESP_ERROR_CHECK(pt_wifi_start_sta(&s_cfg));
    start_keys();
    ui_init(&s_cfg, false);
    pt_httpd_set_ui(ui_handle, NULL, NULL, s_cfg.lan_admin);
    ESP_ERROR_CHECK(pt_httpd_start(s_cfg.port, 0));
    if (!pt_wifi_wait_ip(30000)) {
        ESP_LOGW(TAG, "no IP address yet; will keep retrying");
    }
    if (pt_mdns_start(s_cfg.hostname, s_cfg.port) != ESP_OK) {
        ESP_LOGW(TAG, "mDNS failed to start");
    }
    char ip[16];
    pt_wifi_ip(ip, sizeof(ip));
    ESP_LOGI(TAG, "PT_READY mode=normal ip=%s port=%u host=%s.local", ip, s_cfg.port,
             s_cfg.hostname);
    for (;;) {
        pt_wifi_ip(ip, sizeof(ip));
        pt_led_set(ip[0] ? PT_LED_NORMAL : PT_LED_CONNECTING);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "Pocket Tang %s", pt_version());
    bool setup_requested = s_boot_request == SETUP_MAGIC;
    s_boot_request = 0;
    pt_led_init();
    ESP_ERROR_CHECK(pt_store_init());
    ESP_ERROR_CHECK(pt_store_load_config(&s_cfg));
    ESP_ERROR_CHECK(pt_worker_start());
    ESP_ERROR_CHECK(pt_button_start(on_button));
    pt_console_start();
    {
        /* Show the setup credentials on every boot, so they are available before a button
         * press (generated once per device, renewed by a factory reset). */
        char pw[PT_SETUP_PW_LEN + 1];
        if (pt_store_setup_password(pw) == ESP_OK) {
            ESP_LOGI(TAG, "setup access point password: %s", pw);
        }
        pt_zeroize(pw, sizeof(pw));
    }
    if (!s_cfg.provisioned || setup_requested) {
        setup_mode();
    } else {
        normal_mode();
    }
}

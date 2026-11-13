/*
 * Pocket Tang firmware entry point: load configuration and keys, bring up the network and serve
 * the Tang protocol. Setup mode (SoftAP + captive portal) and the button/LED logic are added in
 * milestone M3.
 */
#include <inttypes.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pt/pt_version.h"
#include "pt_esp.h"

static const char *TAG = "pocket-tang";

typedef struct boot_job {
    esp_err_t result;
    bool created;
} boot_job_t;

/* Runs on the worker: load the key store from NVS or create fresh keys. */
static void load_keys_job(void *arg)
{
    boot_job_t *b = arg;
    static uint8_t blob[PT_KEYSTORE_BLOB_MAX];
    size_t len = 0;
    pt_keystore_t *ks = pt_tang_keystore(pt_engine());
    esp_err_t err = pt_store_load_keys(blob, sizeof(blob), &len);
    b->created = false;
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
        b->created = true;
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

void app_main(void)
{
    ESP_LOGI(TAG, "Pocket Tang %s", pt_version());
    ESP_ERROR_CHECK(pt_store_init());
    pt_config_t cfg;
    ESP_ERROR_CHECK(pt_store_load_config(&cfg));
    ESP_ERROR_CHECK(pt_worker_start());
    pt_console_start();

    if (!cfg.provisioned) {
        ESP_LOGW(TAG, "not provisioned: setup mode is implemented in M3; waiting for "
                      "configuration");
        /* Without setup mode, only the test console can provision. Wait idle. */
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    /* Wi-Fi first: the hardware RNG is only fully random while the radio is running. */
    ESP_ERROR_CHECK(pt_wifi_start_sta(&cfg));
    boot_job_t boot = {0};
    pt_worker_run(load_keys_job, &boot);
    if (boot.result != ESP_OK) {
        ESP_LOGE(TAG, "key store unavailable (%s); Tang disabled", esp_err_to_name(boot.result));
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
    pt_worker_run(log_thumbprints_job, NULL);
    pt_worker_run(set_lock_job, &cfg.locked);

    ESP_ERROR_CHECK(pt_httpd_start(cfg.port, 0));
    if (!pt_wifi_wait_ip(30000)) {
        ESP_LOGW(TAG, "no IP address yet; will keep retrying");
    }
    if (pt_mdns_start(cfg.hostname, cfg.port) != ESP_OK) {
        ESP_LOGW(TAG, "mDNS failed to start");
    }
    char ip[16];
    pt_wifi_ip(ip, sizeof(ip));
    ESP_LOGI(TAG, "PT_READY ip=%s port=%u host=%s.local", ip, cfg.port, cfg.hostname);
    pt_zeroize(&cfg, sizeof(cfg));
}

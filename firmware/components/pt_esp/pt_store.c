/* Persistent storage on NVS. Namespaces: "ptcfg" (configuration), "ptkeys" (key-store blob). */
#include <string.h>

#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "pt_esp.h"
#include "sdkconfig.h"

static const char *TAG = "pt_store";

#define NS_CFG  "ptcfg"
#define NS_KEYS "ptkeys"

esp_err_t pt_store_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* Only for an incompatible layout (first flash or IDF upgrade); never silently otherwise.
         */
        ESP_LOGW(TAG, "NVS layout incompatible (%s), erasing", esp_err_to_name(err));
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

static void get_str(nvs_handle_t h, const char *key, char *out, size_t cap, const char *def)
{
    size_t len = cap;
    if (nvs_get_str(h, key, out, &len) != ESP_OK) {
        strlcpy(out, def, cap);
    }
}

esp_err_t pt_store_load_config(pt_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strlcpy(cfg->hostname, CONFIG_PT_DEFAULT_HOSTNAME, sizeof(cfg->hostname));
    cfg->port = CONFIG_PT_TANG_DEFAULT_PORT;
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_CFG, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK; /* never configured */
    }
    if (err != ESP_OK) {
        return err;
    }
    get_str(h, "ssid", cfg->ssid, sizeof(cfg->ssid), "");
    get_str(h, "pass", cfg->pass, sizeof(cfg->pass), "");
    get_str(h, "host", cfg->hostname, sizeof(cfg->hostname), CONFIG_PT_DEFAULT_HOSTNAME);
    uint16_t port = 0;
    if (nvs_get_u16(h, "port", &port) == ESP_OK && port != 0) {
        cfg->port = port;
    }
    uint8_t u8 = 0;
    cfg->locked = nvs_get_u8(h, "locked", &u8) == ESP_OK && u8 != 0;
    cfg->lan_admin = nvs_get_u8(h, "lanadmin", &u8) == ESP_OK && u8 != 0;
    cfg->mqtt_enabled = nvs_get_u8(h, "mqtt_on", &u8) == ESP_OK && u8 != 0;
    get_str(h, "mqtt_uri", cfg->mqtt_uri, sizeof(cfg->mqtt_uri), "");
    get_str(h, "mqtt_user", cfg->mqtt_user, sizeof(cfg->mqtt_user), "");
    get_str(h, "mqtt_pass", cfg->mqtt_pass, sizeof(cfg->mqtt_pass), "");
    size_t len = sizeof(cfg->admin_salt);
    size_t len2 = sizeof(cfg->admin_hash);
    if (nvs_get_blob(h, "asalt", cfg->admin_salt, &len) == ESP_OK &&
        len == sizeof(cfg->admin_salt) &&
        nvs_get_blob(h, "ahash", cfg->admin_hash, &len2) == ESP_OK &&
        len2 == sizeof(cfg->admin_hash) && nvs_get_u32(h, "aiter", &cfg->admin_iter) == ESP_OK) {
        cfg->admin_set = true;
    }
    nvs_close(h);
    cfg->provisioned = cfg->ssid[0] != '\0';
    return ESP_OK;
}

esp_err_t pt_store_save_config(const pt_config_t *cfg)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_CFG, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_str(h, "ssid", cfg->ssid);
    if (err == ESP_OK) {
        err = nvs_set_str(h, "pass", cfg->pass);
    }
    if (err == ESP_OK) {
        err = nvs_set_str(h, "host", cfg->hostname);
    }
    if (err == ESP_OK) {
        err = nvs_set_u16(h, "port", cfg->port);
    }
    if (err == ESP_OK) {
        err = nvs_set_u8(h, "locked", cfg->locked ? 1 : 0);
    }
    if (err == ESP_OK) {
        err = nvs_set_u8(h, "lanadmin", cfg->lan_admin ? 1 : 0);
    }
    if (err == ESP_OK) {
        err = nvs_set_u8(h, "mqtt_on", cfg->mqtt_enabled ? 1 : 0);
    }
    if (err == ESP_OK) {
        err = nvs_set_str(h, "mqtt_uri", cfg->mqtt_uri);
    }
    if (err == ESP_OK) {
        err = nvs_set_str(h, "mqtt_user", cfg->mqtt_user);
    }
    if (err == ESP_OK) {
        err = nvs_set_str(h, "mqtt_pass", cfg->mqtt_pass);
    }
    if (err == ESP_OK && cfg->admin_set) {
        err = nvs_set_blob(h, "asalt", cfg->admin_salt, sizeof(cfg->admin_salt));
        if (err == ESP_OK) {
            err = nvs_set_blob(h, "ahash", cfg->admin_hash, sizeof(cfg->admin_hash));
        }
        if (err == ESP_OK) {
            err = nvs_set_u32(h, "aiter", cfg->admin_iter);
        }
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t pt_store_load_keys(uint8_t *blob, size_t cap, size_t *len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_KEYS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
    }
    *len = cap;
    err = nvs_get_blob(h, "ks", blob, len);
    nvs_close(h);
    return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
}

esp_err_t pt_store_save_keys(const uint8_t *blob, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_KEYS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(h, "ks", blob, len);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

static esp_err_t erase_ns(const char *ns)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(ns, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_erase_all(h);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t pt_store_factory_reset(void)
{
    ESP_LOGW(TAG, "factory reset: erasing keys, configuration and statistics");
    esp_err_t err = erase_ns(NS_KEYS);
    esp_err_t err2 = erase_ns(NS_CFG);
    esp_err_t err3 = erase_ns("ptstat");
    if (err != ESP_OK || err2 != ESP_OK || err3 != ESP_OK) {
        /* Fall back to erasing the whole partition: keys must not survive a reset. */
        ESP_LOGE(TAG, "namespace erase failed, erasing NVS partition");
        nvs_flash_deinit();
        return nvs_flash_erase();
    }
    return ESP_OK;
}

esp_err_t pt_store_setup_password(char out[PT_SETUP_PW_LEN + 1])
{
    /* No 0/O/1/l/I: the password is read from a serial console and typed on a phone. */
    static const char alphabet[] = "abcdefghijkmnpqrstuvwxyz23456789";
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_CFG, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    size_t len = PT_SETUP_PW_LEN + 1;
    err = nvs_get_str(h, "appass", out, &len);
    if (err == ESP_OK && len == PT_SETUP_PW_LEN + 1) {
        nvs_close(h);
        return ESP_OK;
    }
    /* Called before Wi-Fi starts: enable the SAR ADC entropy source so the hardware RNG is
     * truly random (see the ESP-IDF random number generation documentation). */
    bootloader_random_enable();
    for (int i = 0; i < PT_SETUP_PW_LEN; i++) {
        /* 32 symbols: 5 random bits each, no modulo bias */
        out[i] = alphabet[esp_random() & 31u];
    }
    bootloader_random_disable();
    out[PT_SETUP_PW_LEN] = '\0';
    err = nvs_set_str(h, "appass", out);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t pt_store_load_mqtt_ca(char *pem, size_t cap, size_t *len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_CFG, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
    }
    size_t n = cap;
    err = nvs_get_blob(h, "mqttca", pem, &n);
    nvs_close(h);
    if (err != ESP_OK) {
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
    }
    if (n == 0 || n >= cap || pem[n - 1] != '\0') {
        return ESP_ERR_INVALID_SIZE; /* stored with its terminating NUL */
    }
    *len = n;
    return ESP_OK;
}

esp_err_t pt_store_save_mqtt_ca(const char *pem)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS_CFG, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    if (pem == NULL || pem[0] == '\0') {
        err = nvs_erase_key(h, "mqttca");
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_OK;
        }
    } else {
        err = nvs_set_blob(h, "mqttca", pem, strlen(pem) + 1);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

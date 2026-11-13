/* Wi-Fi station mode with automatic reconnection (exponential backoff), SNTP and mDNS. */
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"
#include "mdns.h"
#include "pt/pt_version.h"
#include "pt_esp.h"
#include "sdkconfig.h"

static const char *TAG = "pt_wifi";

#define BIT_GOT_IP BIT0

static EventGroupHandle_t s_events;
static esp_netif_t *s_sta;
static TimerHandle_t s_retry_timer;
static uint32_t s_backoff_ms = 1000;
static char s_ip[16];

static void retry_cb(TimerHandle_t t)
{
    (void)t;
    esp_wifi_connect();
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *d = data;
        xEventGroupClearBits(s_events, BIT_GOT_IP);
        s_ip[0] = '\0';
        ESP_LOGW(TAG, "disconnected (reason %d), retry in %lu ms", d->reason,
                 (unsigned long)s_backoff_ms);
        xTimerChangePeriod(s_retry_timer, pdMS_TO_TICKS(s_backoff_ms), 0);
        xTimerStart(s_retry_timer, 0);
        s_backoff_ms = s_backoff_ms < 30000 ? s_backoff_ms * 2 : 60000;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *e = data;
        snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&e->ip_info.ip));
        ESP_LOGI(TAG, "got ip: %s", s_ip);
        s_backoff_ms = 1000;
        xEventGroupSetBits(s_events, BIT_GOT_IP);
    }
}

esp_err_t pt_wifi_start_sta(const pt_config_t *cfg)
{
    s_events = xEventGroupCreate();
    s_retry_timer = xTimerCreate("wifi_retry", pdMS_TO_TICKS(1000), pdFALSE, NULL, retry_cb);
    ESP_ERROR_CHECK(esp_netif_init());
    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }
    s_sta = esp_netif_create_default_wifi_sta();
    esp_netif_set_hostname(s_sta, cfg->hostname);
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM)); /* credentials live in our NVS */

    wifi_config_t wc = {0};
    strlcpy((char *)wc.sta.ssid, cfg->ssid, sizeof(wc.sta.ssid));
    strlcpy((char *)wc.sta.password, cfg->pass, sizeof(wc.sta.password));
    /* Refuse open/WEP/WPA networks when a password is set; WPA2 and WPA3 (SAE) are accepted. */
    wc.sta.threshold.authmode = cfg->pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    wc.sta.pmf_cfg.capable = true;
    wc.sta.pmf_cfg.required = false;
    wc.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    wc.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wc.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    pt_zeroize(&wc, sizeof(wc));
    ESP_ERROR_CHECK(esp_wifi_start());
#if CONFIG_PT_WIFI_PS_MIN_MODEM
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_MIN_MODEM));
#else
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
#endif

    esp_sntp_config_t sntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_netif_sntp_init(&sntp);
    ESP_LOGI(TAG, "connecting to SSID \"%s\"", cfg->ssid);
    return ESP_OK;
}

bool pt_wifi_wait_ip(uint32_t timeout_ms)
{
    return (xEventGroupWaitBits(s_events, BIT_GOT_IP, pdFALSE, pdTRUE, pdMS_TO_TICKS(timeout_ms)) &
            BIT_GOT_IP) != 0;
}

void pt_wifi_ip(char *out, size_t cap)
{
    strlcpy(out, s_ip, cap);
}

int pt_wifi_rssi(void)
{
    wifi_ap_record_t ap;
    return esp_wifi_sta_get_ap_info(&ap) == ESP_OK ? ap.rssi : 0;
}

esp_err_t pt_mdns_start(const char *hostname, uint16_t port)
{
    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        return err;
    }
    mdns_hostname_set(hostname);
    mdns_instance_name_set("Pocket Tang");
    mdns_txt_item_t txt[] = {{"path", "/adv"}, {"version", PT_VERSION}};
    return mdns_service_add(NULL, "_http", "_tcp", port, txt, sizeof(txt) / sizeof(txt[0]));
}

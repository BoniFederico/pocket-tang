/*
 * Wi-Fi: station mode with automatic reconnection (exponential backoff), setup mode (WPA2 access
 * point, optionally together with the station so Tang keeps serving), scanning, SNTP and mDNS.
 */
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
static esp_netif_t *s_ap;
static TimerHandle_t s_retry_timer;
static uint32_t s_backoff_ms = 1000;
static char s_ip[16];
static bool s_sta_enabled;

static void retry_cb(TimerHandle_t t)
{
    (void)t;
    esp_wifi_connect();
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        if (s_sta_enabled) {
            esp_wifi_connect();
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *d = data;
        xEventGroupClearBits(s_events, BIT_GOT_IP);
        s_ip[0] = '\0';
        if (!s_sta_enabled) {
            return;
        }
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
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        ESP_LOGI(TAG, "setup client connected");
    }
}

static void common_init(const pt_config_t *cfg, bool with_ap)
{
    s_events = xEventGroupCreate();
    s_retry_timer = xTimerCreate("wifi_retry", pdMS_TO_TICKS(1000), pdFALSE, NULL, retry_cb);
    ESP_ERROR_CHECK(esp_netif_init());
    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(err);
    }
    s_sta = esp_netif_create_default_wifi_sta();
    esp_netif_set_hostname(s_sta, cfg->hostname);
    if (with_ap) {
        s_ap = esp_netif_create_default_wifi_ap(); /* 192.168.4.1/24 with DHCP server */
    }
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM)); /* credentials live in our NVS */
}

static void set_sta_config(const pt_config_t *cfg)
{
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
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    pt_zeroize(&wc, sizeof(wc));
}

static void after_start(void)
{
#if CONFIG_PT_WIFI_PS_MIN_MODEM
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_MIN_MODEM));
#else
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
#endif
    if (s_sta_enabled) {
        esp_sntp_config_t sntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
        esp_netif_sntp_init(&sntp);
    }
}

esp_err_t pt_wifi_start_sta(const pt_config_t *cfg)
{
    common_init(cfg, false);
    s_sta_enabled = true;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    set_sta_config(cfg);
    ESP_ERROR_CHECK(esp_wifi_start());
    after_start();
    ESP_LOGI(TAG, "connecting to SSID \"%s\"", cfg->ssid);
    return ESP_OK;
}

esp_err_t pt_wifi_start_setup(const pt_config_t *cfg, const char *ap_ssid, const char *ap_pass,
                              bool with_sta)
{
    common_init(cfg, true);
    s_sta_enabled = with_sta && cfg->provisioned;
    /* APSTA even without a station connection: scanning needs the station interface. */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    wifi_config_t ap = {0};
    strlcpy((char *)ap.ap.ssid, ap_ssid, sizeof(ap.ap.ssid));
    ap.ap.ssid_len = (uint8_t)strlen(ap_ssid);
    strlcpy((char *)ap.ap.password, ap_pass, sizeof(ap.ap.password));
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap.ap.pairwise_cipher = WIFI_CIPHER_TYPE_CCMP;
    ap.ap.max_connection = 2;
    ap.ap.channel = 6;
    ap.ap.pmf_cfg.required = false;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    pt_zeroize(&ap, sizeof(ap));
    if (s_sta_enabled) {
        set_sta_config(cfg);
    }
    ESP_ERROR_CHECK(esp_wifi_start());
    after_start();
    ESP_LOGI(TAG, "setup access point \"%s\" on %s%s", ap_ssid, PT_AP_IP,
             s_sta_enabled ? " (station kept connected)" : "");
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

int pt_wifi_ap_clients(void)
{
    wifi_sta_list_t list;
    return esp_wifi_ap_get_sta_list(&list) == ESP_OK ? list.num : 0;
}

int pt_wifi_scan(pt_scan_ap_t *out, int max)
{
    wifi_scan_config_t sc = {.show_hidden = false};
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) {
        return 0;
    }
    uint16_t n = 24;
    static wifi_ap_record_t recs[24];
    if (esp_wifi_scan_get_ap_records(&n, recs) != ESP_OK) {
        return 0;
    }
    int count = 0;
    for (uint16_t i = 0; i < n; i++) {
        const char *ssid = (const char *)recs[i].ssid;
        if (ssid[0] == '\0') {
            continue;
        }
        int dup = -1;
        for (int j = 0; j < count; j++) {
            if (strcmp(out[j].ssid, ssid) == 0) {
                dup = j;
                break;
            }
        }
        if (dup >= 0) {
            if (recs[i].rssi > out[dup].rssi) {
                out[dup].rssi = recs[i].rssi;
            }
            continue;
        }
        if (count >= max) {
            break;
        }
        strlcpy(out[count].ssid, ssid, sizeof(out[count].ssid));
        out[count].rssi = recs[i].rssi;
        out[count].secure = recs[i].authmode != WIFI_AUTH_OPEN;
        count++;
    }
    return count;
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

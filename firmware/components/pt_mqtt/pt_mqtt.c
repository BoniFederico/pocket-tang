/*
 * MQTT / Home Assistant integration. See pt_mqtt.h for the constraints.
 *
 * Topics (base = pocket-tang/<device id>):
 *   <base>/availability   "online" / "offline" (retained; "offline" is the last will)
 *   <base>/event          {"event_type":"unlock"|"denied","client":...,"kid":...,"status":...}
 *   <base>/state          {"rssi","uptime_s","unlocks","denied","last_unlock","last_client",
 *                          "version"}
 *   <base>/keys           {"signing":"<S256 thumbprint>","exchange":"<S256 thumbprint>"}
 *   <base>/lock           "ON" / "OFF" (retained)        <base>/lock/set   command
 *   <base>/restart        command ("PRESS")
 * Discovery: homeassistant/device/<device id>/config (device-based discovery, not retained;
 * re-sent on connect and when homeassistant/status becomes "online").
 */
#include "pt_mqtt.h"
#include "sdkconfig.h"

#if CONFIG_PT_MQTT

#include <stdio.h>
#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include "pt/pt_json.h"
#include "pt/pt_version.h"
#include "sdkconfig.h"

static const char *TAG = "pt_mqtt";

#define DISCOVERY_PREFIX "homeassistant"
#define EVENT_QUEUE_LEN  8

typedef struct mq_event {
    uint8_t type; /* pt_tang_event_t */
    int16_t status;
    char client[16];
    char kid[44];
} mq_event_t;

static esp_mqtt_client_handle_t s_client;
static QueueHandle_t s_events;
static pt_mqtt_hooks_t s_hooks;
static char s_dev_id[32];
static char s_base[64];
static char s_hostname[PT_HOST_MAX + 1];
static volatile bool s_connected;
static volatile bool s_need_discovery;
static uint32_t s_dropped;

const char *pt_mqtt_base_topic(void)
{
    return s_base;
}

/* ------------------------------------------------------------------------------------------ */
/* Tang path → queue (must never block)                                                         */
/* ------------------------------------------------------------------------------------------ */

static void on_tang_event(pt_tang_event_t ev, int status, const char *client, const char *kid)
{
    if (s_events == NULL) {
        return;
    }
    mq_event_t e = {.type = (uint8_t)ev, .status = (int16_t)status};
    strlcpy(e.client, client, sizeof(e.client));
    strlcpy(e.kid, kid, sizeof(e.kid));
    if (xQueueSend(s_events, &e, 0) != pdTRUE) {
        s_dropped++; /* never wait: the Tang path has priority */
    }
}

/* ------------------------------------------------------------------------------------------ */
/* Publishing helpers (only ever called from the MQTT tasks, never from the Tang path)          */
/* ------------------------------------------------------------------------------------------ */

static void publish(const char *suffix, const char *payload, int qos, bool retain)
{
    if (s_client == NULL) {
        return;
    }
    char topic[96];
    snprintf(topic, sizeof(topic), "%s/%s", s_base, suffix);
    /* Called from our low-priority tasks only: a blocking publish is fine here and avoids the
     * outbox backlog that esp_mqtt_client_enqueue() builds up under bursts. */
    if (esp_mqtt_client_publish(s_client, topic, payload, 0, qos, retain ? 1 : 0) < 0) {
        s_dropped++;
    }
}

static void publish_state(void)
{
    pt_stats_t st;
    pt_stats_get(&st);
    char buf[320];
    pt_jw_t w;
    pt_jw_init(&w, buf, sizeof(buf));
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "rssi");
    int rssi = pt_wifi_rssi();
    char num[12];
    snprintf(num, sizeof(num), "%d", rssi);
    pt_jw_raw(&w, num, strlen(num));
    pt_jw_key(&w, "uptime_s");
    pt_jw_uint(&w, (uint32_t)(esp_timer_get_time() / 1000000));
    pt_jw_key(&w, "unlocks");
    pt_jw_uint(&w, st.rec_ok);
    pt_jw_key(&w, "denied");
    pt_jw_uint(&w, st.rec_denied);
    pt_jw_key(&w, "last_unlock");
    pt_jw_uint(&w, (uint32_t)st.last_unlock_epoch);
    pt_jw_key(&w, "last_client");
    pt_jw_str(&w, st.last_client);
    pt_jw_key(&w, "version");
    pt_jw_str(&w, pt_version());
    pt_jw_obj_end(&w);
    if (pt_jw_finish(&w, NULL) == PT_OK) {
        publish("state", buf, 0, false);
    }
}

typedef struct keys_view {
    char sig[PT_THP_MAX];
    char exc[PT_THP_MAX];
} keys_view_t;

static void keys_job(void *arg)
{
    keys_view_t *k = arg;
    const pt_keystore_t *ks = pt_tang_keystore(pt_engine());
    const pt_key_t *s = pt_keystore_active(ks, PT_ALG_ES512);
    const pt_key_t *e = pt_keystore_active(ks, PT_ALG_ECMR);
    if (s == NULL || pt_jwk_thumbprint_b64(&s->pub, PT_HASH_SHA256, k->sig, PT_THP_MAX) != PT_OK) {
        k->sig[0] = '\0';
    }
    if (e == NULL || pt_jwk_thumbprint_b64(&e->pub, PT_HASH_SHA256, k->exc, PT_THP_MAX) != PT_OK) {
        k->exc[0] = '\0';
    }
}

static void publish_keys(void)
{
    keys_view_t k;
    if (pt_worker_run(keys_job, &k) != ESP_OK) {
        return;
    }
    char buf[256];
    snprintf(buf, sizeof(buf), "{\"signing\":\"%s\",\"exchange\":\"%s\"}", k.sig, k.exc);
    publish("keys", buf, 0, false);
}

static void publish_lock(bool locked)
{
    publish("lock", locked ? "ON" : "OFF", 1, true);
}

static volatile bool s_lock_dirty;

void pt_mqtt_lock_changed(bool locked)
{
    (void)locked; /* the publisher task reads the current state through the hook */
    s_lock_dirty = true;
}

/* ------------------------------------------------------------------------------------------ */
/* Home Assistant device discovery                                                              */
/* ------------------------------------------------------------------------------------------ */

/* Common start of a component: "<id>":{"p":...,"name":...,"uniq_id":"<dev>_<id>" */
static void comp_begin(pt_jw_t *w, const char *id, const char *platform, const char *name)
{
    char uid[64];
    snprintf(uid, sizeof(uid), "%s_%s", s_dev_id, id);
    pt_jw_key(w, id);
    pt_jw_obj_begin(w);
    pt_jw_key(w, "p");
    pt_jw_str(w, platform);
    pt_jw_key(w, "name");
    pt_jw_str(w, name);
    pt_jw_key(w, "uniq_id");
    pt_jw_str(w, uid);
}

static void kv(pt_jw_t *w, const char *k, const char *v)
{
    pt_jw_key(w, k);
    pt_jw_str(w, v);
}

static void topic_kv(pt_jw_t *w, const char *k, const char *suffix)
{
    char t[96];
    snprintf(t, sizeof(t), "%s/%s", s_base, suffix);
    kv(w, k, t);
}

static void sensor(pt_jw_t *w, const char *id, const char *name, const char *topic, const char *tpl,
                   const char *dev_cla, const char *unit, const char *stat_cla, bool diagnostic,
                   const char *icon)
{
    comp_begin(w, id, "sensor", name);
    topic_kv(w, "stat_t", topic);
    kv(w, "val_tpl", tpl);
    if (dev_cla) {
        kv(w, "dev_cla", dev_cla);
    }
    if (unit) {
        kv(w, "unit_of_meas", unit);
    }
    if (stat_cla) {
        kv(w, "stat_cla", stat_cla);
    }
    if (diagnostic) {
        kv(w, "ent_cat", "diagnostic");
    }
    if (icon) {
        kv(w, "ic", icon);
    }
    pt_jw_obj_end(w);
}

static void publish_discovery(void)
{
    static char buf[4096];
    pt_jw_t w;
    pt_jw_init(&w, buf, sizeof(buf));
    pt_jw_obj_begin(&w);

    pt_jw_key(&w, "dev");
    pt_jw_obj_begin(&w);
    pt_jw_key(&w, "ids");
    pt_jw_arr_begin(&w);
    pt_jw_str(&w, s_dev_id);
    pt_jw_arr_end(&w);
    kv(&w, "name", s_hostname);
    kv(&w, "mf", "Pocket Tang");
    kv(&w, "mdl", "Tang server (" CONFIG_IDF_TARGET ")");
    kv(&w, "sw", pt_version());
    char cu[64];
    char ip[16];
    pt_wifi_ip(ip, sizeof(ip));
    snprintf(cu, sizeof(cu), "http://%s/admin", ip);
    kv(&w, "cu", cu);
    pt_jw_obj_end(&w);

    pt_jw_key(&w, "o");
    pt_jw_obj_begin(&w);
    kv(&w, "name", "pocket-tang");
    kv(&w, "sw", pt_version());
    kv(&w, "url", "https://bonifederico.github.io/pocket-tang/");
    pt_jw_obj_end(&w);

    topic_kv(&w, "avty_t", "availability");

    pt_jw_key(&w, "cmps");
    pt_jw_obj_begin(&w);

    comp_begin(&w, "recovery", "event", "Recovery");
    topic_kv(&w, "stat_t", "event");
    pt_jw_key(&w, "evt_typ");
    pt_jw_arr_begin(&w);
    pt_jw_str(&w, "unlock");
    pt_jw_str(&w, "denied");
    pt_jw_arr_end(&w);
    kv(&w, "ic", "mdi:lock-open-variant");
    pt_jw_obj_end(&w);

    sensor(&w, "last_unlock", "Last unlock", "state",
           "{{ as_datetime(value_json.last_unlock) if value_json.last_unlock | int(0) > 0 else "
           "none }}",
           "timestamp", NULL, NULL, false, NULL);
    sensor(&w, "last_client", "Last client", "state", "{{ value_json.last_client }}", NULL, NULL,
           NULL, false, "mdi:ip-network");
    sensor(&w, "unlocks", "Unlocks", "state", "{{ value_json.unlocks }}", NULL, NULL,
           "total_increasing", false, "mdi:lock-open-check");
    sensor(&w, "denied", "Denied", "state", "{{ value_json.denied }}", NULL, NULL,
           "total_increasing", false, "mdi:lock-alert");
    sensor(&w, "rssi", "Wi-Fi signal", "state", "{{ value_json.rssi }}", "signal_strength", "dBm",
           "measurement", true, NULL);
    sensor(&w, "uptime", "Uptime", "state", "{{ value_json.uptime_s }}", "duration", "s", NULL,
           true, NULL);
    sensor(&w, "version", "Firmware version", "state", "{{ value_json.version }}", NULL, NULL, NULL,
           true, "mdi:chip");
    sensor(&w, "thp_sig", "Signing key thumbprint", "keys", "{{ value_json.signing }}", NULL, NULL,
           NULL, true, "mdi:key");
    sensor(&w, "thp_exc", "Exchange key thumbprint", "keys", "{{ value_json.exchange }}", NULL,
           NULL, NULL, true, "mdi:key-variant");

    comp_begin(&w, "lock", "switch", "Recovery lock");
    topic_kv(&w, "stat_t", "lock");
    topic_kv(&w, "cmd_t", "lock/set");
    kv(&w, "ic", "mdi:shield-lock");
    pt_jw_obj_end(&w);

    comp_begin(&w, "restart", "button", "Restart");
    topic_kv(&w, "cmd_t", "restart");
    kv(&w, "dev_cla", "restart");
    kv(&w, "ent_cat", "config");
    pt_jw_obj_end(&w);

    pt_jw_obj_end(&w); /* cmps */
    pt_jw_obj_end(&w);
    size_t len = 0;
    if (pt_jw_finish(&w, &len) != PT_OK) {
        ESP_LOGE(TAG, "discovery payload too large");
        return;
    }
    char topic[96];
    snprintf(topic, sizeof(topic), DISCOVERY_PREFIX "/device/%s/config", s_dev_id);
    esp_mqtt_client_publish(s_client, topic, buf, (int)len, 1, 0);
    ESP_LOGI(TAG, "discovery published (%u bytes)", (unsigned)len);
}

static void publish_all(void)
{
    publish("availability", "online", 1, true);
    publish_discovery();
    publish_lock(s_hooks.get_lock ? s_hooks.get_lock() : false);
    publish_keys();
    publish_state();
}

/* ------------------------------------------------------------------------------------------ */
/* MQTT events (esp-mqtt task)                                                                  */
/* ------------------------------------------------------------------------------------------ */

static bool topic_is(const esp_mqtt_event_handle_t e, const char *topic)
{
    size_t n = strlen(topic);
    return (size_t)e->topic_len == n && memcmp(e->topic, topic, n) == 0;
}

static bool data_is(const esp_mqtt_event_handle_t e, const char *s)
{
    size_t n = strlen(s);
    return (size_t)e->data_len == n && memcmp(e->data, s, n) == 0;
}

static void on_mqtt(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    esp_mqtt_event_handle_t e = data;
    char t[96];
    switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "PT_MQTT connected");
        s_connected = true;
        esp_mqtt_client_subscribe(s_client, DISCOVERY_PREFIX "/status", 1);
        snprintf(t, sizeof(t), "%s/lock/set", s_base);
        esp_mqtt_client_subscribe(s_client, t, 1);
        snprintf(t, sizeof(t), "%s/restart", s_base);
        esp_mqtt_client_subscribe(s_client, t, 1);
        s_need_discovery = true;
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "PT_MQTT disconnected");
        s_connected = false;
        break;
    case MQTT_EVENT_DATA:
        if (e->current_data_offset != 0 || e->data_len != e->total_data_len) {
            break; /* fragmented message: none of ours are */
        }
        if (topic_is(e, DISCOVERY_PREFIX "/status")) {
            if (data_is(e, "online")) {
                ESP_LOGI(TAG, "Home Assistant online: re-sending discovery");
                s_need_discovery = true;
            }
            break;
        }
        snprintf(t, sizeof(t), "%s/lock/set", s_base);
        if (topic_is(e, t)) {
            if ((data_is(e, "ON") || data_is(e, "OFF")) && s_hooks.set_lock) {
                bool on = data_is(e, "ON");
                ESP_LOGW(TAG, "recovery lock %s from MQTT", on ? "ON" : "OFF");
                s_hooks.set_lock(on);
                publish_lock(on);
            }
            break;
        }
        snprintf(t, sizeof(t), "%s/restart", s_base);
        if (topic_is(e, t) && data_is(e, "PRESS") && s_hooks.restart) {
            ESP_LOGW(TAG, "restart requested from MQTT");
            s_hooks.restart();
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGW(TAG, "MQTT error");
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------------------------------ */
/* Publisher task (low priority)                                                                */
/* ------------------------------------------------------------------------------------------ */

static void publisher_task(void *arg)
{
    (void)arg;
    const TickType_t period = pdMS_TO_TICKS(CONFIG_PT_MQTT_STATE_INTERVAL_S * 1000);
    const TickType_t min_gap = pdMS_TO_TICKS(1000); /* coalesce state updates during bursts */
    TickType_t last_state = 0;
    bool state_dirty = false;
    for (;;) {
        mq_event_t ev;
        bool got = xQueueReceive(s_events, &ev, pdMS_TO_TICKS(250)) == pdTRUE;
        if (!s_connected) {
            continue; /* events while disconnected are not replayed (counters still are) */
        }
        if (s_need_discovery) {
            s_need_discovery = false;
            /* HA recommends a small random delay after its birth message. */
            vTaskDelay(pdMS_TO_TICKS(200 + (esp_random() % 1500)));
            publish_all();
            last_state = xTaskGetTickCount();
            state_dirty = false;
        }
        if (s_lock_dirty) {
            s_lock_dirty = false;
            publish_lock(s_hooks.get_lock ? s_hooks.get_lock() : false);
        }
        if (got) {
            char buf[160];
            snprintf(buf, sizeof(buf),
                     "{\"event_type\":\"%s\",\"client\":\"%s\",\"kid\":\"%s\",\"status\":%d}",
                     ev.type == PT_EV_REC_OK ? "unlock" : "denied", ev.client, ev.kid, ev.status);
            publish("event", buf, 0, false);
            state_dirty = true;
        }
        TickType_t now = xTaskGetTickCount();
        if ((state_dirty && now - last_state >= min_gap) || now - last_state >= period) {
            publish_state();
            last_state = now;
            state_dirty = false;
        }
    }
}

esp_err_t pt_mqtt_start(const pt_config_t *cfg, const pt_mqtt_hooks_t *hooks)
{
    if (!cfg->mqtt_enabled || cfg->mqtt_uri[0] == '\0') {
        ESP_LOGI(TAG, "MQTT integration disabled");
        return ESP_OK;
    }
    bool tls = strncmp(cfg->mqtt_uri, "mqtts://", 8) == 0;
    if (!tls && strncmp(cfg->mqtt_uri, "mqtt://", 7) != 0) {
        ESP_LOGE(TAG, "unsupported MQTT URI (use mqtt:// or mqtts://)");
        return ESP_ERR_INVALID_ARG;
    }
    if (!tls && cfg->mqtt_pass[0] != '\0') {
        ESP_LOGW(TAG, "MQTT password sent without TLS: prefer mqtts://");
    }
    s_hooks = *hooks;
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_dev_id, sizeof(s_dev_id), "pockettang_%02x%02x%02x%02x%02x%02x", mac[0], mac[1],
             mac[2], mac[3], mac[4], mac[5]);
    snprintf(s_base, sizeof(s_base), "pocket-tang/%s", s_dev_id);
    strlcpy(s_hostname, cfg->hostname, sizeof(s_hostname));

    static char will_topic[96];
    snprintf(will_topic, sizeof(will_topic), "%s/availability", s_base);
    esp_mqtt_client_config_t mc = {
        .broker.address.uri = cfg->mqtt_uri,
        .credentials.client_id = s_dev_id,
        .credentials.username = cfg->mqtt_user[0] ? cfg->mqtt_user : NULL,
        .credentials.authentication.password = cfg->mqtt_pass[0] ? cfg->mqtt_pass : NULL,
        .session.keepalive = 30,
        .session.last_will =
            {.topic = will_topic, .msg = "offline", .msg_len = 7, .qos = 1, .retain = 1},
        .network.reconnect_timeout_ms = 10000,
        .network.timeout_ms = 10000,
        .buffer.size = 1024,
        .buffer.out_size = 4096,
        .task.priority = 2, /* below the crypto worker (6) and the HTTP server (5) */
        .task.stack_size = 6144,
        .outbox.limit = 16384,
    };
    if (tls) {
        /* A configured private CA (typical for a LAN broker) takes precedence over the public
         * certificate bundle. The server certificate and host name are always verified. */
        static char ca[PT_MQTT_CA_MAX];
        size_t ca_len = 0;
        if (pt_store_load_mqtt_ca(ca, sizeof(ca), &ca_len) == ESP_OK) {
            mc.broker.verification.certificate = ca;
            mc.broker.verification.certificate_len = ca_len;
            ESP_LOGI(TAG, "TLS with the configured broker CA");
        } else {
            mc.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
            ESP_LOGI(TAG, "TLS with the public certificate bundle");
        }
    }
    s_events = xQueueCreate(EVENT_QUEUE_LEN, sizeof(mq_event_t));
    s_client = esp_mqtt_client_init(&mc);
    if (s_events == NULL || s_client == NULL) {
        return ESP_ERR_NO_MEM;
    }
    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, on_mqtt, NULL);
    if (xTaskCreate(publisher_task, "pt_mqtt_pub", 4096, NULL, 1, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    pt_events_set_listener(on_tang_event);
    ESP_LOGI(TAG, "connecting to %s as %s", cfg->mqtt_uri, s_dev_id);
    return esp_mqtt_client_start(s_client);
}

#else /* !CONFIG_PT_MQTT */

esp_err_t pt_mqtt_start(const pt_config_t *cfg, const pt_mqtt_hooks_t *hooks)
{
    (void)cfg;
    (void)hooks;
    return ESP_OK;
}

void pt_mqtt_lock_changed(bool locked)
{
    (void)locked;
}

const char *pt_mqtt_base_topic(void)
{
    return "";
}

#endif /* CONFIG_PT_MQTT */

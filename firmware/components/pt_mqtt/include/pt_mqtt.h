/**
 * @file pt_mqtt.h
 * @brief Optional MQTT client with Home Assistant MQTT discovery.
 *
 * Design constraints (milestone M6):
 *  - never blocks or slows down the Tang path: the crypto worker only drops events into a small
 *    queue with a zero timeout (events are discarded when the queue is full); everything else
 *    runs on low-priority tasks;
 *  - no key material is ever published: only public thumbprints, counters and addresses;
 *  - TLS to the broker (mqtts://) with the ESP-IDF certificate bundle;
 *  - availability through a retained last-will message; discovery is re-sent when Home
 *    Assistant announces itself on `homeassistant/status`.
 */
#pragma once

#include <stdbool.h>

#include "esp_err.h"
#include "pt_esp.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Callbacks into the application (called on the MQTT task). */
typedef struct pt_mqtt_hooks {
    void (*set_lock)(bool locked); /**< switch "Recovery lock" toggled from Home Assistant */
    bool (*get_lock)(void);
    void (*restart)(void); /**< button "Restart" pressed */
} pt_mqtt_hooks_t;

/**
 * @brief Start the MQTT integration if @p cfg enables it. Safe to call once after the station
 *        obtained an IP address.
 */
esp_err_t pt_mqtt_start(const pt_config_t *cfg, const pt_mqtt_hooks_t *hooks);

/** @brief Publish the lock state after a change made elsewhere (admin page). */
void pt_mqtt_lock_changed(bool locked);

/** @brief Base topic, e.g. "pocket-tang/pockettang_704bca02bb80" (empty when not started). */
const char *pt_mqtt_base_topic(void);

#ifdef __cplusplus
}
#endif

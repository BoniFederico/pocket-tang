/* Runtime statistics shared between the worker, the HTTP task and reporting (console, admin
 * page, MQTT). Protected by a spinlock; never blocks. */
#include <string.h>
#include <sys/time.h>

#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pt_esp.h"

static pt_stats_t s_stats;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

void pt_stats_event(pt_tang_event_t ev, int status, const char *client, uint32_t crypto_us)
{
    (void)status;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    /* Before SNTP sync the clock starts at 1970; report 0 ("unknown") in that case. */
    int64_t now = tv.tv_sec > 1700000000 ? (int64_t)tv.tv_sec : 0;
    taskENTER_CRITICAL(&s_lock);
    switch (ev) {
    case PT_EV_REC_OK:
        s_stats.rec_ok++;
        s_stats.last_unlock_epoch = now;
        strlcpy(s_stats.last_client, client ? client : "", sizeof(s_stats.last_client));
        s_stats.rec_last_us = crypto_us;
        if (crypto_us > s_stats.rec_max_us) {
            s_stats.rec_max_us = crypto_us;
        }
        s_stats.rec_total_us += crypto_us;
        break;
    case PT_EV_REC_DENIED:
        s_stats.rec_denied++;
        break;
    case PT_EV_ADV:
        s_stats.adv++;
        break;
    default:
        break;
    }
    taskEXIT_CRITICAL(&s_lock);
}

void pt_stats_busy(void)
{
    taskENTER_CRITICAL(&s_lock);
    s_stats.busy++;
    taskEXIT_CRITICAL(&s_lock);
}

void pt_stats_httpd_stack(uint32_t free_bytes)
{
    taskENTER_CRITICAL(&s_lock);
    s_stats.httpd_stack_free = free_bytes;
    taskEXIT_CRITICAL(&s_lock);
}

void pt_stats_get(pt_stats_t *out)
{
    TaskHandle_t w = xTaskGetHandle("pt_worker");
    uint32_t wfree = w ? (uint32_t)uxTaskGetStackHighWaterMark(w) * sizeof(StackType_t) : 0;
    taskENTER_CRITICAL(&s_lock);
    s_stats.worker_stack_free = wfree;
    *out = s_stats;
    taskEXIT_CRITICAL(&s_lock);
    out->heap_free = (uint32_t)esp_get_free_heap_size();
    out->heap_min_free = (uint32_t)esp_get_minimum_free_heap_size();
    out->heap_largest_block = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
}

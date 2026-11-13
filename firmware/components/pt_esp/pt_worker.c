/*
 * Crypto worker: a single task owns the Tang engine (keys, advertisement cache). All engine
 * access is serialised through a bounded queue, so HTTP handlers, the admin UI and MQTT never
 * touch key material concurrently, and a burst of requests cannot exhaust memory: when the
 * queue is full the caller answers 503 immediately.
 */
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "pt_esp.h"
#include "sdkconfig.h"

static const char *TAG = "pt_worker";

typedef struct job {
    pt_job_fn fn;
    void *arg;
    SemaphoreHandle_t done;
} job_t;

static QueueHandle_t s_queue;
static TaskHandle_t s_task;
static pt_tang_t s_tang; /* only accessed on the worker task */

pt_tang_t *pt_engine(void)
{
    return &s_tang;
}

static int esp_rng(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    /* Hardware RNG; true random while Wi-Fi is running (keys are generated after Wi-Fi start). */
    esp_fill_random(buf, len);
    return 0;
}

static void worker_task(void *arg)
{
    (void)arg;
    job_t job;
    for (;;) {
        if (xQueueReceive(s_queue, &job, portMAX_DELAY) == pdTRUE) {
            job.fn(job.arg);
            xSemaphoreGive(job.done);
        }
    }
}

esp_err_t pt_worker_start(void)
{
    pt_crypto_set_rng(esp_rng, NULL);
    pt_tang_init(&s_tang);
    s_queue = xQueueCreate(CONFIG_PT_WORKER_QUEUE_LEN, sizeof(job_t));
    if (s_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }
    /* Priority above the HTTP server so accepted work finishes quickly; below Wi-Fi/lwIP. */
    if (xTaskCreate(worker_task, "pt_worker", CONFIG_PT_WORKER_STACK, NULL, 6, &s_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t pt_worker_run(pt_job_fn fn, void *arg)
{
    if (xTaskGetCurrentTaskHandle() == s_task) {
        fn(arg); /* already on the worker */
        return ESP_OK;
    }
    StaticSemaphore_t sem_buf;
    job_t job = {.fn = fn, .arg = arg, .done = xSemaphoreCreateBinaryStatic(&sem_buf)};
    if (xQueueSend(s_queue, &job, 0) != pdTRUE) {
        vSemaphoreDelete(job.done);
        return ESP_ERR_TIMEOUT;
    }
    /* Once queued, the job always completes; wait for it (no timeout: it references our stack). */
    xSemaphoreTake(job.done, portMAX_DELAY);
    vSemaphoreDelete(job.done);
    return ESP_OK;
}

esp_err_t pt_engine_persist_keys(void)
{
    static uint8_t blob[PT_KEYSTORE_BLOB_MAX];
    size_t len = 0;
    if (pt_keystore_save(pt_tang_keystore(&s_tang), blob, sizeof(blob), &len) != PT_OK) {
        return ESP_FAIL;
    }
    esp_err_t err = pt_store_save_keys(blob, len);
    pt_zeroize(blob, sizeof(blob));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "saving keys failed: %s", esp_err_to_name(err));
    }
    return err;
}

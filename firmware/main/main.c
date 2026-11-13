#include <inttypes.h>

#include "esp_log.h"
#include "esp_system.h"
#include "pt/pt_version.h"

static const char *TAG = "pocket-tang";

void app_main(void)
{
    ESP_LOGI(TAG, "Pocket Tang %s starting", pt_version());
    ESP_LOGI(TAG, "free heap: %" PRIu32 " bytes", esp_get_free_heap_size());
}

/* Captive-portal DNS responder: answers every A query on the setup access point with the AP
 * address, so clients open the setup page. Parsing is done by the fuzzed core (pt_dns). */
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "pt/pt_dns.h"
#include "pt_esp.h"

static const char *TAG = "pt_dnsd";

static void dnsd_task(void *arg)
{
    (void)arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(53)};
    inet_pton(AF_INET, PT_AP_IP, &sa.sin_addr);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        ESP_LOGE(TAG, "cannot bind UDP 53");
        if (fd >= 0) {
            close(fd);
        }
        vTaskDelete(NULL);
        return;
    }
    uint8_t ip[4];
    memcpy(ip, &sa.sin_addr.s_addr, 4);
    static uint8_t q[PT_DNS_MAX];
    static uint8_t r[PT_DNS_MAX];
    for (;;) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        int n = recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&from, &flen);
        if (n <= 0) {
            continue;
        }
        size_t m = pt_dns_answer(q, (size_t)n, ip, r, sizeof(r));
        if (m > 0) {
            sendto(fd, r, m, 0, (struct sockaddr *)&from, flen);
        }
    }
}

esp_err_t pt_dnsd_start(void)
{
    return xTaskCreate(dnsd_task, "pt_dnsd", 3072, NULL, 4, NULL) == pdPASS ? ESP_OK
                                                                            : ESP_ERR_NO_MEM;
}

/*
 * HTTP front-end on the portable event-driven server (core/net/pt_server.c).
 *
 * One task polls the listening sockets. Complete requests are routed by the portable core
 * (pt_tang_route) so status codes match upstream tangd; Tang work runs on the crypto worker.
 * Requests that arrive on the setup access point (and, if enabled, /admin on the LAN) go to the
 * UI handler instead. esp_http_server is not used: it reads request heads with blocking
 * receives on a single task, so one slow client could stall all others (see pt_server.h).
 */
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pt/pt_server.h"
#include "pt_esp.h"
#include "sdkconfig.h"

static const char *TAG = "pt_httpd";

static pt_srv_t s_srv;
static pt_ui_handler_fn s_ui_handler;
static void *s_ui_ctx;
static char s_ap_ip[16];
static bool s_lan_admin;

/* Response buffer shared by the (single) server task and the worker during a synchronous job. */
static char s_out[PT_TANG_RESP_MAX];

typedef struct tang_job {
    const pt_tang_req_t *req;
    const uint8_t *body;
    size_t body_len;
    pt_tang_resp_t resp;
    const char *client;
} tang_job_t;

static void tang_job_fn(void *arg)
{
    tang_job_t *j = arg;
    int64_t t0 = esp_timer_get_time();
    pt_tang_handle(pt_engine(), j->req, j->body, j->body_len, s_out, sizeof(s_out), &j->resp);
    uint32_t us = (uint32_t)(esp_timer_get_time() - t0);
    if (j->req->route == PT_ROUTE_REC) {
        pt_stats_event(j->resp.status == 200 ? PT_EV_REC_OK : PT_EV_REC_DENIED, j->resp.status,
                       j->client, j->req->kid, us);
        if (j->resp.status == 200) {
            pt_led_blip();
        }
        ESP_LOGI(TAG, "rec %s from %s -> %d (%lu us)", j->req->kid, j->client, j->resp.status,
                 (unsigned long)us);
    } else if (j->req->route == PT_ROUTE_ADV || j->req->route == PT_ROUTE_ADV_KID) {
        pt_stats_event(PT_EV_ADV, j->resp.status, j->client, j->req->kid, us);
    }
}

static void tang_request(const pt_srv_request_t *req, pt_srv_response_t *resp)
{
    pt_tang_req_t treq;
    pt_tang_route(req->method, req->target, req->target_len, &treq);
    if (treq.status != 0) {
        resp->status = treq.status;
        return;
    }
    tang_job_t job = {
        .req = &treq, .body = req->body, .body_len = req->body_len, .client = req->peer};
    if (pt_worker_run(tang_job_fn, &job) != ESP_OK) {
        pt_stats_busy();
        ESP_LOGW(TAG, "worker busy, 503 for %s", req->peer);
        resp->status = 503;
        return;
    }
    resp->status = job.resp.status;
    if (job.resp.status == 200) {
        resp->content_type = job.resp.content_type;
        resp->body = s_out;
        resp->body_len = job.resp.body_len;
    }
}

static bool is_admin_path(const pt_srv_request_t *req)
{
    return req->target_len >= 6 && memcmp(req->target, "/admin", 6) == 0;
}

static void handler(void *ctx, const pt_srv_request_t *req, pt_srv_response_t *resp)
{
    (void)ctx;
    bool on_ap = s_ap_ip[0] != '\0' && strcmp(req->local, s_ap_ip) == 0;
    if (s_ui_handler != NULL && (on_ap || (s_lan_admin && is_admin_path(req)))) {
        s_ui_handler(s_ui_ctx, req, resp, on_ap);
        return;
    }
    tang_request(req, resp);
}

static void on_reject(void *ctx, int status, const char *peer)
{
    (void)ctx;
    ESP_LOGW(TAG, "%s: request rejected with %d", peer, status);
}

static void server_task(void *arg)
{
    (void)arg;
    for (;;) {
        pt_srv_poll(&s_srv, 200);
        pt_stats_httpd_stack((uint32_t)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
    }
}

void pt_httpd_set_ui(pt_ui_handler_fn fn, void *ctx, const char *ap_ip, bool lan_admin)
{
    s_ui_handler = fn;
    s_ui_ctx = ctx;
    strlcpy(s_ap_ip, ap_ip ? ap_ip : "", sizeof(s_ap_ip));
    s_lan_admin = lan_admin;
}

esp_err_t pt_httpd_start(uint16_t tang_port, uint16_t extra_port)
{
    pt_srv_config_t cfg = {
        .ports = {tang_port, extra_port != tang_port ? extra_port : 0},
        .bind_addr = NULL,
        .max_conns = CONFIG_PT_HTTPD_MAX_SOCKETS,
        .max_per_peer = CONFIG_PT_HTTPD_MAX_SOCKETS > 2 ? CONFIG_PT_HTTPD_MAX_SOCKETS - 2 : 1,
        .request_timeout_ms = 5000,
        .send_timeout_ms = 5000,
        .handler = handler,
        .on_reject = on_reject,
    };
    if (pt_srv_open(&s_srv, &cfg) != PT_OK) {
        return ESP_FAIL;
    }
    if (xTaskCreate(server_task, "pt_http", 6144, NULL, 5, NULL) != pdPASS) {
        pt_srv_close(&s_srv);
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "HTTP server on port %u", tang_port);
    return ESP_OK;
}

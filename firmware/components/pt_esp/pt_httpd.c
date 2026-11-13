/*
 * HTTP front-end for the Tang endpoints on top of esp_http_server.
 *
 * Every method/path is routed by the portable core (pt_tang_route) so that status codes match
 * upstream tangd exactly. Bodies are bounded (413 above PT_TANG_MAX_BODY) and read with the
 * server's receive timeout. The engine runs on the crypto worker; if its queue is full the
 * client gets 503 immediately.
 */
#include <string.h>

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "pt_esp.h"
#include "sdkconfig.h"

static const char *TAG = "pt_httpd";

/* Buffers are owned by the (single) HTTP server task and handed to the worker for the duration
 * of a synchronous job. */
static uint8_t s_body[PT_TANG_MAX_BODY];
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
                       j->client, us);
        ESP_LOGI(TAG, "rec %s from %s -> %d (%lu us)", j->req->kid, j->client, j->resp.status,
                 (unsigned long)us);
    } else if (j->req->route == PT_ROUTE_ADV || j->req->route == PT_ROUTE_ADV_KID) {
        pt_stats_event(PT_EV_ADV, j->resp.status, j->client, us);
    }
}

static void client_ip(httpd_req_t *req, char *out, size_t cap)
{
    struct sockaddr_in6 addr;
    socklen_t len = sizeof(addr);
    out[0] = '\0';
    if (getpeername(httpd_req_to_sockfd(req), (struct sockaddr *)&addr, &len) != 0) {
        return;
    }
    if (addr.sin6_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) {
        inet_ntop(AF_INET, &addr.sin6_addr.un.u32_addr[3], out, cap);
    } else if (addr.sin6_family == AF_INET6) {
        inet_ntop(AF_INET6, &addr.sin6_addr, out, cap);
    } else {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr, out, cap);
    }
}

static esp_err_t send_status(httpd_req_t *req, int status)
{
    char line[48];
    snprintf(line, sizeof(line), "%d %s", status,
             status == 400   ? "Bad Request"
             : status == 403 ? "Forbidden"
             : status == 404 ? "Not Found"
             : status == 405 ? "Method Not Allowed"
             : status == 408 ? "Request Timeout"
             : status == 413 ? "Payload Too Large"
             : status == 503 ? "Service Unavailable"
                             : "Internal Server Error");
    httpd_resp_set_status(req, line);
    return httpd_resp_send(req, NULL, 0);
}

static const char *method_name(int m)
{
    switch (m) {
    case HTTP_GET:
        return "GET";
    case HTTP_POST:
        return "POST";
    case HTTP_HEAD:
        return "HEAD";
    case HTTP_PUT:
        return "PUT";
    case HTTP_DELETE:
        return "DELETE";
    case HTTP_OPTIONS:
        return "OPTIONS";
    case HTTP_PATCH:
        return "PATCH";
    default:
        return "OTHER";
    }
}

static esp_err_t tang_handler(httpd_req_t *req)
{
    pt_tang_req_t treq;
    pt_tang_route(method_name(req->method), req->uri, strlen(req->uri), &treq);
    if (treq.status != 0) {
        return send_status(req, treq.status);
    }
    size_t body_len = 0;
    if (treq.route == PT_ROUTE_REC) {
        if (req->content_len > sizeof(s_body)) {
            httpd_resp_set_hdr(req, "Connection", "close");
            return send_status(req, 413);
        }
        while (body_len < req->content_len) {
            int n = httpd_req_recv(req, (char *)s_body + body_len, req->content_len - body_len);
            if (n == HTTPD_SOCK_ERR_TIMEOUT) {
                return send_status(req, 408);
            }
            if (n <= 0) {
                return ESP_FAIL; /* connection closed */
            }
            body_len += (size_t)n;
        }
    }
    char ip[48];
    client_ip(req, ip, sizeof(ip));
    tang_job_t job = {.req = &treq, .body = s_body, .body_len = body_len, .client = ip};
    if (pt_worker_run(tang_job_fn, &job) != ESP_OK) {
        pt_stats_busy();
        ESP_LOGW(TAG, "worker busy, 503 for %s", ip);
        return send_status(req, 503);
    }
    pt_zeroize(s_body, body_len);
    pt_stats_httpd_stack((uint32_t)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
    if (job.resp.status != 200) {
        return send_status(req, job.resp.status);
    }
    httpd_resp_set_type(req, job.resp.content_type);
    return httpd_resp_send(req, s_out, (ssize_t)job.resp.body_len);
}

static esp_err_t not_found(httpd_req_t *req, httpd_err_code_t err)
{
    (void)err;
    return send_status(req, 404);
}

esp_err_t pt_httpd_start(uint16_t port)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = port;
    cfg.ctrl_port = 32768 + (port % 1000);
    cfg.max_open_sockets = CONFIG_PT_HTTPD_MAX_SOCKETS;
    cfg.lru_purge_enable = true; /* idle clients cannot pin all sockets */
    cfg.recv_wait_timeout = 5;
    cfg.send_wait_timeout = 5;
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 12;
    cfg.stack_size = 6144;
    cfg.task_priority = 5;
    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &cfg);
    if (err != ESP_OK) {
        return err;
    }
    static const httpd_method_t methods[] = {HTTP_GET,    HTTP_POST,    HTTP_HEAD, HTTP_PUT,
                                             HTTP_DELETE, HTTP_OPTIONS, HTTP_PATCH};
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        httpd_uri_t u = {.uri = "/*", .method = methods[i], .handler = tang_handler};
        httpd_register_uri_handler(server, &u);
    }
    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, not_found);
    ESP_LOGI(TAG, "Tang HTTP server on port %u", port);
    return ESP_OK;
}

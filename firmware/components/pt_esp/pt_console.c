/*
 * Serial test console, compiled only with CONFIG_PT_TEST_CONSOLE (test profile). It lets the
 * hardware-in-the-loop runner provision the device and read statistics without a human.
 * Release images do not contain this code (see firmware/profiles/sdkconfig.test.defaults).
 */
#include "sdkconfig.h"

#include "pt_esp.h"

#if CONFIG_PT_TEST_CONSOLE

#include <stdio.h>
#include <string.h>

#include "argtable3/argtable3.h"
#include "esp_console.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

static struct {
    struct arg_str *ssid;
    struct arg_str *pass;
    struct arg_str *host;
    struct arg_int *port;
    struct arg_end *end;
} s_prov;

static int cmd_provision(int argc, char **argv)
{
    if (arg_parse(argc, argv, (void **)&s_prov) != 0) {
        arg_print_errors(stderr, s_prov.end, argv[0]);
        return 1;
    }
    pt_config_t cfg;
    pt_store_load_config(&cfg);
    strlcpy(cfg.ssid, s_prov.ssid->sval[0], sizeof(cfg.ssid));
    strlcpy(cfg.pass, s_prov.pass->sval[0], sizeof(cfg.pass));
    if (s_prov.host->count) {
        strlcpy(cfg.hostname, s_prov.host->sval[0], sizeof(cfg.hostname));
    }
    if (s_prov.port->count) {
        cfg.port = (uint16_t)s_prov.port->ival[0];
    }
    esp_err_t err = pt_store_save_config(&cfg);
    pt_zeroize(&cfg, sizeof(cfg));
    printf("PT_PROVISION %s\n", err == ESP_OK ? "OK" : esp_err_to_name(err));
    return err == ESP_OK ? 0 : 1;
}

static int cmd_stats(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    pt_stats_t s;
    pt_stats_get(&s);
    char ip[16];
    pt_wifi_ip(ip, sizeof(ip));
    /* One machine-readable line for the HIL runner. */
    printf("PT_STATS ip=%s rssi=%d uptime_s=%lld rec_ok=%lu rec_denied=%lu adv=%lu busy=%lu "
           "rec_last_us=%lu rec_max_us=%lu rec_avg_us=%lu heap_free=%lu heap_min=%lu "
           "heap_largest=%lu worker_stack_free=%lu httpd_stack_free=%lu\n",
           ip, pt_wifi_rssi(), (long long)(esp_timer_get_time() / 1000000), (unsigned long)s.rec_ok,
           (unsigned long)s.rec_denied, (unsigned long)s.adv, (unsigned long)s.busy,
           (unsigned long)s.rec_last_us, (unsigned long)s.rec_max_us,
           (unsigned long)(s.rec_ok ? s.rec_total_us / s.rec_ok : 0), (unsigned long)s.heap_free,
           (unsigned long)s.heap_min_free, (unsigned long)s.heap_largest_block,
           (unsigned long)s.worker_stack_free, (unsigned long)s.httpd_stack_free);
    return 0;
}

static void rotate_job(void *arg)
{
    esp_err_t *res = arg;
    pt_err_t err = pt_keystore_rotate(pt_tang_keystore(pt_engine()));
    if (err == PT_OK) {
        *res = pt_engine_persist_keys();
        if (*res == ESP_OK && pt_tang_refresh(pt_engine()) != PT_OK) {
            *res = ESP_FAIL;
        }
    } else {
        *res = err == PT_ERR_LIMIT ? ESP_ERR_NO_MEM : ESP_FAIL;
    }
}

static int cmd_rotate(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    esp_err_t res = ESP_FAIL;
    if (pt_worker_run(rotate_job, &res) != ESP_OK) {
        res = ESP_ERR_TIMEOUT;
    }
    printf("PT_ROTATE %s\n", res == ESP_OK ? "OK" : esp_err_to_name(res));
    return res == ESP_OK ? 0 : 1;
}

static int cmd_reboot(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("PT_REBOOT\n");
    fflush(stdout);
    esp_restart();
    return 0;
}

static int cmd_factory_reset(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    esp_err_t err = pt_store_factory_reset();
    printf("PT_FACTORY_RESET %s\n", err == ESP_OK ? "OK" : esp_err_to_name(err));
    fflush(stdout);
    esp_restart();
    return 0;
}

void pt_console_start(void)
{
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t rc = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    rc.prompt = "pt>";
    rc.max_cmdline_length = 256;
    esp_console_dev_uart_config_t uc = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    if (esp_console_new_repl_uart(&uc, &rc, &repl) != ESP_OK) {
        return;
    }
    s_prov.ssid = arg_str1(NULL, NULL, "<ssid>", "Wi-Fi SSID");
    s_prov.pass = arg_str1(NULL, NULL, "<password>", "Wi-Fi password");
    s_prov.host = arg_str0("n", "hostname", "<name>", "hostname");
    s_prov.port = arg_int0("p", "port", "<port>", "Tang port");
    s_prov.end = arg_end(4);
    const esp_console_cmd_t cmds[] = {
        {.command = "provision",
         .help = "store Wi-Fi credentials (test builds)",
         .func = cmd_provision,
         .argtable = &s_prov},
        {.command = "stats", .help = "print statistics", .func = cmd_stats},
        {.command = "rotate", .help = "rotate Tang keys", .func = cmd_rotate},
        {.command = "reboot", .help = "restart", .func = cmd_reboot},
        {.command = "factory-reset",
         .help = "erase keys and configuration",
         .func = cmd_factory_reset},
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        esp_console_cmd_register(&cmds[i]);
    }
    esp_console_start_repl(repl);
    ESP_LOGW("pt_console", "TEST CONSOLE ENABLED - not for production use");
}

#else

void pt_console_start(void)
{
}

#endif

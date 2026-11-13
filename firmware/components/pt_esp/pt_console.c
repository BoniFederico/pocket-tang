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
#include "pt/pt_web.h"

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

static struct {
    struct arg_str *pw;
    struct arg_lit *lan;
    struct arg_end *end;
} s_adm;

/* Test builds only: set the admin password (and optionally LAN admin) without the setup AP. */
static int cmd_admin(int argc, char **argv)
{
    if (arg_parse(argc, argv, (void **)&s_adm) != 0) {
        arg_print_errors(stderr, s_adm.end, argv[0]);
        return 1;
    }
    const char *pw = s_adm.pw->sval[0];
    pt_pw_t v;
    if (pt_pw_set(&v, pw, strlen(pw), PT_PW_ITER_DEFAULT) != PT_OK) {
        printf("PT_ADMIN invalid\n");
        return 1;
    }
    pt_config_t cfg;
    pt_store_load_config(&cfg);
    memcpy(cfg.admin_salt, v.salt, sizeof(cfg.admin_salt));
    memcpy(cfg.admin_hash, v.hash, sizeof(cfg.admin_hash));
    cfg.admin_iter = v.iter;
    cfg.admin_set = true;
    cfg.lan_admin = s_adm.lan->count > 0;
    esp_err_t err = pt_store_save_config(&cfg);
    pt_zeroize(&cfg, sizeof(cfg));
    pt_zeroize(&v, sizeof(v));
    printf("PT_ADMIN %s\n", err == ESP_OK ? "OK" : esp_err_to_name(err));
    return err == ESP_OK ? 0 : 1;
}

static struct {
    struct arg_str *uri;
    struct arg_str *user;
    struct arg_str *pass;
    struct arg_lit *off;
    struct arg_end *end;
} s_mq;

/* Test builds only: configure the MQTT integration (takes effect after a reboot). */
static int cmd_mqtt(int argc, char **argv)
{
    if (arg_parse(argc, argv, (void **)&s_mq) != 0) {
        arg_print_errors(stderr, s_mq.end, argv[0]);
        return 1;
    }
    pt_config_t cfg;
    pt_store_load_config(&cfg);
    cfg.mqtt_enabled = s_mq.off->count == 0;
    strlcpy(cfg.mqtt_uri, s_mq.uri->sval[0], sizeof(cfg.mqtt_uri));
    strlcpy(cfg.mqtt_user, s_mq.user->count ? s_mq.user->sval[0] : "", sizeof(cfg.mqtt_user));
    strlcpy(cfg.mqtt_pass, s_mq.pass->count ? s_mq.pass->sval[0] : "", sizeof(cfg.mqtt_pass));
    esp_err_t err = pt_store_save_config(&cfg);
    pt_zeroize(&cfg, sizeof(cfg));
    printf("PT_MQTT_CFG %s\n", err == ESP_OK ? "OK" : esp_err_to_name(err));
    return err == ESP_OK ? 0 : 1;
}

static struct {
    struct arg_int *ms;
    struct arg_end *end;
} s_btn;

static int cmd_button(int argc, char **argv)
{
    if (arg_parse(argc, argv, (void **)&s_btn) != 0) {
        arg_print_errors(stderr, s_btn.end, argv[0]);
        return 1;
    }
    pt_button_simulate((uint32_t)s_btn.ms->ival[0]);
    printf("PT_BUTTON_SIM %d\n", s_btn.ms->ival[0]);
    return 0;
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
    s_btn.ms = arg_int1(NULL, NULL, "<ms>", "hold duration in milliseconds");
    s_btn.end = arg_end(1);
    s_adm.pw = arg_str1(NULL, NULL, "<password>", "admin password (8-64 chars)");
    s_adm.lan = arg_lit0("l", "lan", "allow the admin page on the LAN");
    s_adm.end = arg_end(2);
    s_mq.uri = arg_str1(NULL, NULL, "<uri>", "mqtt://host:1883 or mqtts://host:8883");
    s_mq.user = arg_str0("u", "user", "<user>", "MQTT user");
    s_mq.pass = arg_str0("P", "password", "<password>", "MQTT password");
    s_mq.off = arg_lit0(NULL, "off", "disable the integration");
    s_mq.end = arg_end(4);
    const esp_console_cmd_t cmds[] = {
        {.command = "provision",
         .help = "store Wi-Fi credentials (test builds)",
         .func = cmd_provision,
         .argtable = &s_prov},
        {.command = "stats", .help = "print statistics", .func = cmd_stats},
        {.command = "rotate", .help = "rotate Tang keys", .func = cmd_rotate},
        {.command = "reboot", .help = "restart", .func = cmd_reboot},
        {.command = "button",
         .help = "simulate holding BOOT",
         .func = cmd_button,
         .argtable = &s_btn},
        {.command = "admin",
         .help = "set admin password (test builds)",
         .func = cmd_admin,
         .argtable = &s_adm},
        {.command = "mqtt",
         .help = "configure MQTT (test builds)",
         .func = cmd_mqtt,
         .argtable = &s_mq},
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

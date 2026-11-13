/*
 * Setup and admin web UI.
 *
 * Reachable on the setup access point (always) and, when "LAN admin" is enabled, under /admin
 * on the LAN. All pages are server-rendered, need no JavaScript and are sent with a strict
 * Content-Security-Policy. Authentication: a PBKDF2 admin password, one session cookie
 * (HttpOnly, SameSite=Strict, 10 min), a CSRF token in every form and login back-off.
 * The UI never shows or exports private keys.
 *
 * Paths:
 *   GET  /admin                dashboard, first-time setup form, or login form
 *   POST /admin/login          log in
 *   POST /admin/logout         log out
 *   POST /admin/setup          save Wi-Fi / hostname / port / admin password / options, reboot
 *   POST /admin/rotate         rotate Tang keys
 *   POST /admin/purge          delete rotated keys (breaks bindings to them)
 *   POST /admin/lock           toggle the /rec kill switch
 *   POST /admin/reboot         restart (leaves setup mode)
 *   POST /admin/factory-reset  erase keys and configuration (type RESET to confirm)
 * On the access point every other path redirects to /admin (captive portal).
 */
#include "ui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pt/pt_version.h"
#include "pt/pt_web.h"
#include "sdkconfig.h"

static const char *TAG = "pt_ui";

#define SESSION_TTL_S 600

static pt_config_t *s_cfg;
static bool s_setup_mode;
static pt_session_t s_session;
static pt_ratelimit_t s_rl;
static char s_csrf[PT_TOKEN_B64];
static uint32_t s_last_change_s;

/* Output buffers: the HTTP server runs one request at a time on one task. */
static char s_page[7168];
static size_t s_len;
static char s_hdrs[768];

static uint32_t now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

uint32_t ui_idle_seconds(void)
{
    return now_s() - s_last_change_s;
}

void ui_init(pt_config_t *cfg, bool setup_mode)
{
    s_cfg = cfg;
    s_setup_mode = setup_mode;
    s_last_change_s = now_s();
}

/* ------------------------------------------------------------------------------------------ */
/* Output helpers                                                                              */
/* ------------------------------------------------------------------------------------------ */

static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out(const char *fmt, ...)
{
    if (s_len >= sizeof(s_page)) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s_page + s_len, sizeof(s_page) - s_len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        s_len += (size_t)n;
        if (s_len > sizeof(s_page)) {
            s_len = sizeof(s_page); /* truncated: page_end() turns this into a 500 */
        }
    }
}

/* Escaped text. */
static void out_text(const char *s)
{
    char esc[200];
    if (pt_html_escape(s, esc, sizeof(esc)) == PT_OK) {
        out("%s", esc);
    }
}

static const char SEC_HEADERS[] = "Cache-Control: no-store\r\n"
                                  "X-Frame-Options: DENY\r\n"
                                  "X-Content-Type-Options: nosniff\r\n"
                                  "Referrer-Policy: no-referrer\r\n"
                                  "Content-Security-Policy: default-src 'none'; "
                                  "style-src 'unsafe-inline'; form-action 'self'; "
                                  "frame-ancestors 'none'\r\n";

static void page_begin(const char *title)
{
    s_len = 0;
    out("<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
        "<title>Pocket Tang - %s</title><style>"
        "body{font-family:system-ui,sans-serif;max-width:40rem;margin:auto;padding:1rem;"
        "background:#f6f7f9;color:#1d2330}"
        "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.6rem}"
        "section{background:#fff;border:1px solid #dde1e7;border-radius:8px;padding:1rem;"
        "margin:1rem 0}"
        "label{display:block;margin:.6rem 0 .2rem;font-weight:600}"
        "input,select{width:100%%;padding:.5rem;box-sizing:border-box;border:1px solid #bbc;"
        "border-radius:6px}"
        "input[type=checkbox]{width:auto}"
        "button{padding:.55rem 1rem;border:0;border-radius:6px;background:#2457c5;color:#fff;"
        "margin:.6rem .4rem 0 0;cursor:pointer}"
        "button.warn{background:#b3261e}"
        "code{word-break:break-all;font-size:.85rem}"
        "table{width:100%%;border-collapse:collapse}td{padding:.25rem;border-bottom:1px solid"
        " #eee;vertical-align:top}"
        ".note{color:#555;font-size:.9rem}.err{color:#b3261e;font-weight:600}"
        ".ok{color:#1b7a3a;font-weight:600}"
        "</style></head><body><h1>Pocket Tang</h1>",
        title);
}

static void page_end(pt_srv_response_t *resp, int status)
{
    out("<p class=note>Pocket Tang %s</p></body></html>", pt_version());
    if (s_len >= sizeof(s_page)) {
        resp->status = 500;
        return;
    }
    resp->status = status;
    resp->content_type = "text/html; charset=utf-8";
    if (resp->headers == NULL) {
        resp->headers = SEC_HEADERS;
    }
    resp->body = s_page;
    resp->body_len = s_len;
}

static void redirect(pt_srv_response_t *resp, const char *location)
{
    snprintf(s_hdrs, sizeof(s_hdrs), "Location: %s\r\n%s", location, SEC_HEADERS);
    resp->status = 303;
    resp->headers = s_hdrs;
    resp->body = NULL;
    resp->body_len = 0;
}

static void csrf_field(void)
{
    out("<input type=hidden name=csrf value=\"%s\">", s_csrf);
}

/* ------------------------------------------------------------------------------------------ */
/* Request helpers                                                                             */
/* ------------------------------------------------------------------------------------------ */

static bool path_is(const pt_srv_request_t *req, const char *p)
{
    size_t n = strlen(p);
    return req->target_len == n && memcmp(req->target, p, n) == 0;
}

static bool logged_in(const pt_srv_request_t *req)
{
    const char *cookie = NULL;
    size_t clen = 0;
    if (!pt_http_header(req->head, req->head_len, "cookie", &cookie, &clen) || clen > 512) {
        return false;
    }
    char tmp[513];
    memcpy(tmp, cookie, clen);
    tmp[clen] = '\0';
    return pt_session_check_cookie(&s_session, tmp, now_s());
}

static bool form(const pt_srv_request_t *req, const char *name, char *out_buf, size_t cap)
{
    return pt_form_get((const char *)req->body, req->body_len, name, out_buf, cap, NULL) == PT_OK;
}

/* First-time setup: no admin password yet, and only on the setup access point. */
static bool first_time(bool on_ap)
{
    return on_ap && !s_cfg->admin_set;
}

/* State-changing request authorisation: session + CSRF token. */
static bool authorised_post(const pt_srv_request_t *req)
{
    char tok[PT_TOKEN_B64 + 4];
    return strcmp(req->method, "POST") == 0 && logged_in(req) &&
           form(req, "csrf", tok, sizeof(tok)) &&
           pt_session_check_csrf(&s_session, tok, strlen(tok));
}

/* ------------------------------------------------------------------------------------------ */
/* Worker jobs (key store access)                                                              */
/* ------------------------------------------------------------------------------------------ */

typedef struct keys_view {
    unsigned n;
    struct {
        char thp[PT_THP_MAX];
        bool sig;
        bool rotated;
    } k[PT_KEYS_MAX];
    bool locked;
} keys_view_t;

static void keys_view_job(void *arg)
{
    keys_view_t *v = arg;
    const pt_keystore_t *ks = pt_tang_keystore(pt_engine());
    v->n = 0;
    for (unsigned i = 0; i < pt_keystore_count(ks) && i < PT_KEYS_MAX; i++) {
        const pt_key_t *k = pt_keystore_at(ks, i);
        if (pt_jwk_thumbprint_b64(&k->pub, PT_HASH_SHA256, v->k[v->n].thp, PT_THP_MAX) == PT_OK) {
            v->k[v->n].sig = k->alg == PT_ALG_ES512;
            v->k[v->n].rotated = k->rotated;
            v->n++;
        }
    }
    v->locked = pt_engine()->locked;
}

typedef struct key_op {
    int op; /* 1 rotate, 2 purge, 3 set lock */
    bool lock;
    esp_err_t result;
    unsigned purged;
} key_op_t;

static void key_op_job(void *arg)
{
    key_op_t *o = arg;
    pt_tang_t *t = pt_engine();
    o->result = ESP_OK;
    if (o->op == 1) {
        pt_err_t err = pt_keystore_rotate(pt_tang_keystore(t));
        o->result = err == PT_OK ? ESP_OK : err == PT_ERR_LIMIT ? ESP_ERR_NO_MEM : ESP_FAIL;
    } else if (o->op == 2) {
        o->purged = pt_keystore_purge_rotated(pt_tang_keystore(t));
    } else if (o->op == 3) {
        pt_tang_set_locked(t, o->lock);
        return;
    }
    if (o->result == ESP_OK) {
        o->result = pt_engine_persist_keys();
    }
    if (o->result == ESP_OK && pt_tang_refresh(t) != PT_OK) {
        o->result = ESP_FAIL;
    }
}

static void restart_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

static void schedule_restart(void)
{
    xTaskCreate(restart_task, "pt_restart", 2048, NULL, 2, NULL);
}

/* ------------------------------------------------------------------------------------------ */
/* Pages                                                                                       */
/* ------------------------------------------------------------------------------------------ */

static void setup_form(bool initial)
{
    static pt_scan_ap_t aps[16];
    static int n_aps = -1;
    static uint32_t scanned_at;
    if (s_setup_mode && (n_aps < 0 || now_s() - scanned_at > 30)) {
        n_aps = pt_wifi_scan(aps, 16);
        scanned_at = now_s();
    }
    out("<form method=post action=/admin/setup>");
    if (!initial) {
        csrf_field();
    }
    out("<label for=ssid>Wi-Fi network (2.4 GHz)</label>"
        "<input id=ssid name=ssid list=ssids maxlength=32 required value=\"");
    out_text(s_cfg->ssid);
    out("\"><datalist id=ssids>");
    for (int i = 0; i < n_aps; i++) {
        out("<option value=\"");
        out_text(aps[i].ssid);
        out("\">%d dBm%s</option>", aps[i].rssi, aps[i].secure ? "" : " (open)");
    }
    out("</datalist>"
        "<label for=pass>Wi-Fi password</label>"
        "<input id=pass name=pass type=password maxlength=64 autocomplete=off "
        "placeholder=\"%s\">",
        s_cfg->provisioned ? "unchanged if empty" : "");
    out("<label for=host>Hostname (mDNS: name.local)</label>"
        "<input id=host name=host maxlength=32 pattern=\"[A-Za-z0-9-]{1,32}\" required value=\"");
    out_text(s_cfg->hostname);
    out("\"><label for=port>Tang HTTP port</label>"
        "<input id=port name=port type=number min=1 max=65535 required value=%u>",
        s_cfg->port);
    out("<label for=admin>%s</label>"
        "<input id=admin name=admin type=password minlength=%d maxlength=%d %s "
        "autocomplete=new-password>"
        "<label for=admin2>Repeat admin password</label>"
        "<input id=admin2 name=admin2 type=password maxlength=%d autocomplete=new-password>",
        initial ? "Admin password (8-64 characters)" : "New admin password (empty: unchanged)",
        PT_PW_MIN, PT_PW_MAX, initial ? "required" : "", PT_PW_MAX);
    out("<label><input type=checkbox name=lanadmin value=1 %s> Allow the admin page on the "
        "LAN at http://%s.local/admin (plain HTTP: see the security notes)</label>",
        s_cfg->lan_admin ? "checked" : "", s_cfg->hostname);
    out("<button type=submit>Save and restart</button></form>");
}

static void dashboard(const pt_srv_request_t *req, bool on_ap, const char *msg, bool msg_ok)
{
    (void)req;
    keys_view_t v;
    memset(&v, 0, sizeof(v));
    pt_worker_run(keys_view_job, &v);
    pt_stats_t st;
    pt_stats_get(&st);
    char ip[16];
    pt_wifi_ip(ip, sizeof(ip));

    page_begin("Admin");
    if (msg != NULL) {
        out("<p class=%s>", msg_ok ? "ok" : "err");
        out_text(msg);
        out("</p>");
    }
    out("<section><h2>Status</h2><table>"
        "<tr><td>Mode</td><td>%s</td></tr>"
        "<tr><td>LAN address</td><td>%s:%u (%s.local)</td></tr>"
        "<tr><td>Wi-Fi signal</td><td>%d dBm</td></tr>"
        "<tr><td>Uptime</td><td>%lu s</td></tr>"
        "<tr><td>Recoveries</td><td>%lu ok, %lu denied</td></tr>"
        "<tr><td>Last client</td><td>%s</td></tr>"
        "<tr><td>Recovery lock</td><td>%s</td></tr>"
        "</table></section>",
        s_setup_mode ? "setup" : "normal", ip[0] ? ip : "not connected", s_cfg->port,
        s_cfg->hostname, pt_wifi_rssi(), (unsigned long)now_s(), (unsigned long)st.rec_ok,
        (unsigned long)st.rec_denied, st.last_client[0] ? st.last_client : "-",
        v.locked ? "<b>LOCKED</b> (recoveries refused)" : "off");

    out("<section><h2>Keys</h2><p class=note>Thumbprints (SHA-256, RFC 7638). Use the "
        "signing key thumbprint as <code>thp</code> when binding with Clevis.</p><table>");
    for (unsigned i = 0; i < v.n; i++) {
        out("<tr><td>%s%s</td><td><code>%s</code></td></tr>", v.k[i].sig ? "signing" : "exchange",
            v.k[i].rotated ? " (rotated)" : "", v.k[i].thp);
    }
    out("</table><form method=post action=/admin/rotate>");
    csrf_field();
    out("<button>Rotate keys</button></form>"
        "<form method=post action=/admin/purge>");
    csrf_field();
    out("<button class=warn>Delete rotated keys</button><span class=note> Clients still "
        "bound to rotated keys will no longer unlock.</span></form>"
        "<form method=post action=/admin/lock>");
    csrf_field();
    out("<input type=hidden name=lock value=%d><button%s>%s recovery</button></form></section>",
        v.locked ? 0 : 1, v.locked ? "" : " class=warn", v.locked ? "Unlock" : "Lock");

    out("<section><h2>Configuration</h2>");
    setup_form(false);
    out("</section>");

    out("<section><h2>Device</h2><form method=post action=/admin/reboot>");
    csrf_field();
    out("<button>%s</button></form>", s_setup_mode ? "Leave setup mode (restart)" : "Restart");
    out("<form method=post action=/admin/factory-reset>");
    csrf_field();
    out("<label for=confirm>Factory reset: erases Wi-Fi settings and the Tang keys. "
        "<b>Every Clevis binding to this device stops working.</b> Type RESET to confirm."
        "</label><input id=confirm name=confirm autocomplete=off>"
        "<button class=warn>Factory reset</button></form>");
    out("<form method=post action=/admin/logout>");
    csrf_field();
    out("<button>Log out</button></form></section>");
    (void)on_ap;
}

static void login_page(pt_srv_response_t *resp, const char *msg)
{
    page_begin("Log in");
    out("<section><h2>Log in</h2>");
    if (msg != NULL) {
        out("<p class=err>");
        out_text(msg);
        out("</p>");
    }
    out("<form method=post action=/admin/login><label for=pw>Admin password</label>"
        "<input id=pw name=password type=password autofocus required maxlength=%d>"
        "<button>Log in</button></form></section>",
        PT_PW_MAX);
    page_end(resp, msg ? 403 : 200);
}

static void first_time_page(pt_srv_response_t *resp, const char *msg)
{
    page_begin("Setup");
    out("<section><h2>Welcome</h2><p>Connect Pocket Tang to your Wi-Fi network and choose an "
        "admin password. The device restarts and serves Tang at "
        "<code>http://&lt;hostname&gt;.local</code>.</p>");
    if (msg != NULL) {
        out("<p class=err>");
        out_text(msg);
        out("</p>");
    }
    setup_form(true);
    out("</section>");
    page_end(resp, msg ? 400 : 200);
}

/* ------------------------------------------------------------------------------------------ */
/* Actions                                                                                     */
/* ------------------------------------------------------------------------------------------ */

static bool valid_hostname(const char *h)
{
    size_t n = strlen(h);
    if (n == 0 || n > PT_HOST_MAX || h[0] == '-' || h[n - 1] == '-') {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        char c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-')) {
            return false;
        }
    }
    return true;
}

/* Returns an error message, or NULL on success (config saved). */
static const char *do_setup(const pt_srv_request_t *req, bool initial)
{
    pt_config_t c = *s_cfg;
    char ssid[PT_SSID_MAX + 1];
    char pass[PT_PASS_MAX + 1] = "";
    char host[PT_HOST_MAX + 1];
    char port_s[8];
    char a1[PT_PW_MAX + 1] = "";
    char a2[PT_PW_MAX + 1] = "";
    char lan[4] = "";
    const char *err = NULL;
    if (!form(req, "ssid", ssid, sizeof(ssid)) || ssid[0] == '\0') {
        return "Wi-Fi network name missing or too long.";
    }
    (void)form(req, "pass", pass, sizeof(pass));
    if (!form(req, "host", host, sizeof(host)) || !valid_hostname(host)) {
        return "Hostname: 1-32 letters, digits or '-'.";
    }
    if (!form(req, "port", port_s, sizeof(port_s))) {
        return "Port missing.";
    }
    char *end = NULL;
    long port = strtol(port_s, &end, 10);
    if (end == NULL || *end != '\0' || port < 1 || port > 65535) {
        return "Port must be 1-65535.";
    }
    (void)form(req, "admin", a1, sizeof(a1));
    (void)form(req, "admin2", a2, sizeof(a2));
    (void)form(req, "lanadmin", lan, sizeof(lan));
    if (pass[0] != '\0' && (strlen(pass) < 8 || strlen(pass) > 63)) {
        err = "Wi-Fi password must be 8-63 characters.";
    } else if (pass[0] == '\0' && (!c.provisioned || strcmp(ssid, c.ssid) != 0)) {
        /* open networks are not supported: require a password for a new network */
        err = "Wi-Fi password required for a new network.";
    } else if ((initial || a1[0] != '\0') && strcmp(a1, a2) != 0) {
        err = "Admin passwords do not match.";
    } else if ((initial || a1[0] != '\0') && !pt_pw_acceptable(a1, strlen(a1))) {
        err = "Admin password must be 8-64 printable characters.";
    }
    if (err == NULL) {
        strlcpy(c.ssid, ssid, sizeof(c.ssid));
        if (pass[0] != '\0') {
            strlcpy(c.pass, pass, sizeof(c.pass));
        }
        strlcpy(c.hostname, host, sizeof(c.hostname));
        c.port = (uint16_t)port;
        c.lan_admin = lan[0] == '1';
        c.provisioned = true;
        if (a1[0] != '\0') {
            pt_pw_t v;
            if (pt_pw_set(&v, a1, strlen(a1), PT_PW_ITER_DEFAULT) != PT_OK) {
                err = "Could not hash the password.";
            } else {
                memcpy(c.admin_salt, v.salt, sizeof(c.admin_salt));
                memcpy(c.admin_hash, v.hash, sizeof(c.admin_hash));
                c.admin_iter = v.iter;
                c.admin_set = true;
            }
            pt_zeroize(&v, sizeof(v));
        }
    }
    if (err == NULL && pt_store_save_config(&c) != ESP_OK) {
        err = "Saving the configuration failed.";
    }
    if (err == NULL) {
        *s_cfg = c;
        s_last_change_s = now_s();
        ESP_LOGI(TAG, "configuration saved (ssid \"%s\", host %s, port %u)", c.ssid, c.hostname,
                 c.port);
    }
    pt_zeroize(&c, sizeof(c));
    pt_zeroize(pass, sizeof(pass));
    pt_zeroize(a1, sizeof(a1));
    pt_zeroize(a2, sizeof(a2));
    return err;
}

static void do_login(const pt_srv_request_t *req, pt_srv_response_t *resp)
{
    uint32_t now = now_s();
    if (!pt_ratelimit_allowed(&s_rl, now)) {
        login_page(resp, "Too many attempts. Wait a moment and try again.");
        resp->status = 429;
        return;
    }
    char pw[PT_PW_MAX + 1];
    pt_pw_t v;
    memcpy(v.salt, s_cfg->admin_salt, sizeof(v.salt));
    memcpy(v.hash, s_cfg->admin_hash, sizeof(v.hash));
    v.iter = s_cfg->admin_iter;
    bool ok = s_cfg->admin_set && form(req, "password", pw, sizeof(pw)) &&
              pt_pw_check(&v, pw, strlen(pw));
    pt_zeroize(pw, sizeof(pw));
    pt_zeroize(&v, sizeof(v));
    if (!ok) {
        pt_ratelimit_fail(&s_rl, now);
        ESP_LOGW(TAG, "failed admin login from %s", req->peer);
        login_page(resp, "Wrong password.");
        return;
    }
    pt_ratelimit_ok(&s_rl);
    char cookie[PT_TOKEN_B64];
    if (pt_session_new(&s_session, now, SESSION_TTL_S, cookie, s_csrf) != PT_OK) {
        resp->status = 500;
        return;
    }
    ESP_LOGI(TAG, "admin login from %s", req->peer);
    snprintf(s_hdrs, sizeof(s_hdrs),
             "Location: /admin\r\nSet-Cookie: " PT_SESSION_COOKIE
             "=%s; Path=/admin; Max-Age=%d; HttpOnly; SameSite=Strict\r\n%s",
             cookie, SESSION_TTL_S, SEC_HEADERS);
    pt_zeroize(cookie, sizeof(cookie));
    resp->status = 303;
    resp->headers = s_hdrs;
}

/* ------------------------------------------------------------------------------------------ */

static bool host_is_ours(const pt_srv_request_t *req)
{
    const char *h = NULL;
    size_t n = 0;
    if (!pt_http_header(req->head, req->head_len, "host", &h, &n)) {
        return false;
    }
    char host[64];
    if (n >= sizeof(host)) {
        return false;
    }
    memcpy(host, h, n);
    host[n] = '\0';
    char *colon = strchr(host, ':');
    if (colon != NULL) {
        *colon = '\0';
    }
    char local[PT_HOST_MAX + 8];
    snprintf(local, sizeof(local), "%s.local", s_cfg->hostname);
    return strcmp(host, PT_AP_IP) == 0 || strcasecmp(host, local) == 0 ||
           strcmp(host, req->local) == 0;
}

void ui_handle(void *ctx, const pt_srv_request_t *req, pt_srv_response_t *resp, bool on_ap)
{
    (void)ctx;
    resp->headers = NULL;
    bool is_admin = req->target_len >= 6 && memcmp(req->target, "/admin", 6) == 0;
    /* Captive portal: anything else on the AP (OS connectivity probes...) goes to the UI. */
    if (on_ap && (!is_admin || !host_is_ours(req))) {
        redirect(resp, "http://" PT_AP_IP "/admin");
        return;
    }
    bool get = strcmp(req->method, "GET") == 0;
    bool post = strcmp(req->method, "POST") == 0;

    if (path_is(req, "/admin") || path_is(req, "/admin/")) {
        if (!get) {
            resp->status = 405;
            return;
        }
        if (first_time(on_ap)) {
            first_time_page(resp, NULL);
        } else if (!s_cfg->admin_set) {
            resp->status = 404; /* LAN admin without a password: never */
        } else if (logged_in(req)) {
            dashboard(req, on_ap, NULL, true);
            page_end(resp, 200);
        } else {
            login_page(resp, NULL);
        }
        return;
    }
    if (!post) {
        resp->status = path_is(req, "/admin/login") ? 405 : 404;
        return;
    }
    if (path_is(req, "/admin/login")) {
        do_login(req, resp);
        return;
    }
    if (path_is(req, "/admin/setup") && first_time(on_ap)) {
        const char *err = do_setup(req, true);
        if (err != NULL) {
            first_time_page(resp, err);
            return;
        }
        page_begin("Saved");
        out("<section><p class=ok>Saved. Pocket Tang restarts and joins \"");
        out_text(s_cfg->ssid);
        out("\". Reconnect your device to that network; Tang will answer at "
            "<code>http://");
        out_text(s_cfg->hostname);
        out(".local%s</code>.</p></section>", s_cfg->port == 80 ? "" : ":<port>");
        page_end(resp, 200);
        schedule_restart();
        return;
    }
    if (!authorised_post(req)) {
        login_page(resp, "Session expired, please log in again.");
        return;
    }
    s_session.expires = now_s() + SESSION_TTL_S; /* sliding expiry on activity */
    if (path_is(req, "/admin/logout")) {
        pt_session_end(&s_session);
        redirect(resp, "/admin");
        return;
    }
    if (path_is(req, "/admin/setup")) {
        const char *err = do_setup(req, false);
        dashboard(req, on_ap, err ? err : "Saved. Restarting to apply the settings...",
                  err == NULL);
        page_end(resp, err ? 400 : 200);
        if (err == NULL) {
            schedule_restart();
        }
        return;
    }
    if (path_is(req, "/admin/rotate") || path_is(req, "/admin/purge") ||
        path_is(req, "/admin/lock")) {
        key_op_t op = {.op = path_is(req, "/admin/rotate")  ? 1
                             : path_is(req, "/admin/purge") ? 2
                                                            : 3};
        char lock[4] = "0";
        if (op.op == 3) {
            (void)form(req, "lock", lock, sizeof(lock));
            op.lock = lock[0] == '1';
            s_cfg->locked = op.lock;
            pt_store_save_config(s_cfg);
        }
        if (pt_worker_run(key_op_job, &op) != ESP_OK) {
            op.result = ESP_ERR_TIMEOUT;
        }
        const char *msg =
            op.op == 1
                ? (op.result == ESP_OK           ? "Keys rotated. Old bindings keep "
                                                   "working until you delete rotated keys."
                   : op.result == ESP_ERR_NO_MEM ? "Key store full: delete rotated keys first."
                                                 : "Rotation failed.")
            : op.op == 2 ? (op.result == ESP_OK ? "Rotated keys deleted." : "Failed.")
                         : (op.lock ? "Recovery locked." : "Recovery unlocked.");
        ESP_LOGW(TAG, "admin action %s from %s: %s", req->target, req->peer, msg);
        s_last_change_s = now_s();
        dashboard(req, on_ap, msg, op.result == ESP_OK);
        page_end(resp, 200);
        return;
    }
    if (path_is(req, "/admin/reboot")) {
        page_begin("Restarting");
        out("<section><p class=ok>Restarting...</p></section>");
        page_end(resp, 200);
        schedule_restart();
        return;
    }
    if (path_is(req, "/admin/factory-reset")) {
        char confirm[8] = "";
        (void)form(req, "confirm", confirm, sizeof(confirm));
        if (strcmp(confirm, "RESET") != 0) {
            dashboard(req, on_ap, "Type RESET to confirm the factory reset.", false);
            page_end(resp, 400);
            return;
        }
        ESP_LOGW(TAG, "factory reset requested from the admin page by %s", req->peer);
        pt_store_factory_reset();
        page_begin("Factory reset");
        out("<section><p class=ok>Keys and settings erased. The device restarts in setup "
            "mode.</p></section>");
        page_end(resp, 200);
        schedule_restart();
        return;
    }
    resp->status = 404;
}

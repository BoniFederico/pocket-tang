/*
 * Status LED patterns and BOOT button handling.
 *
 * Button (GPIO0 on the reference board, active low, also the boot strapping pin, so only runtime
 * presses are detected):
 *   held < 3 s   : ignored
 *   held 3..10 s : setup mode (keys kept)        LED blinks very fast from 3 s
 *   held >= 10 s : factory reset (keys erased)   LED solid on from 10 s
 * The action happens on release, so the user sees the LED before letting go.
 */
#include <string.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "pt_esp.h"
#include "sdkconfig.h"

static const char *TAG = "pt_io";

#define TICK_MS  50
#define SETUP_MS 3000
#define RESET_MS 10000

static volatile pt_led_state_t s_led = PT_LED_OFF;
static volatile int s_blip_ticks;
static volatile uint32_t s_sim_ms;
static esp_timer_handle_t s_led_timer;
static uint32_t s_tick;

static const char *led_name(pt_led_state_t s)
{
    switch (s) {
    case PT_LED_OFF:
        return "off";
    case PT_LED_CONNECTING:
        return "connecting";
    case PT_LED_NORMAL:
        return "normal";
    case PT_LED_SETUP:
        return "setup";
    case PT_LED_HOLD_SETUP:
        return "hold-setup";
    case PT_LED_HOLD_RESET:
        return "hold-reset";
    case PT_LED_ERROR:
        return "error";
    default:
        return "?";
    }
}

static void led_write(bool on)
{
#if CONFIG_PT_LED_GPIO >= 0
    gpio_set_level(CONFIG_PT_LED_GPIO, CONFIG_PT_LED_ACTIVE_HIGH ? on : !on);
#else
    (void)on;
#endif
}

static void led_tick(void *arg)
{
    (void)arg;
    s_tick++;
    bool on = false;
    switch (s_led) {
    case PT_LED_CONNECTING:
        on = (s_tick / 2) % 2 == 0; /* 5 Hz */
        break;
    case PT_LED_SETUP:
        on = (s_tick / 10) % 2 == 0; /* 1 Hz */
        break;
    case PT_LED_HOLD_SETUP:
        on = s_tick % 2 == 0; /* 10 Hz */
        break;
    case PT_LED_HOLD_RESET:
        on = true;
        break;
    case PT_LED_ERROR: {
        unsigned p = s_tick % 30; /* three short blinks every 1.5 s */
        on = p < 6 && p % 2 == 0;
        break;
    }
    case PT_LED_NORMAL:
    case PT_LED_OFF:
    default:
        on = false;
        break;
    }
    if (s_blip_ticks > 0) {
        s_blip_ticks--;
        on = !on;
    }
    led_write(on);
}

void pt_led_init(void)
{
#if CONFIG_PT_LED_GPIO >= 0
    gpio_reset_pin(CONFIG_PT_LED_GPIO);
    gpio_set_direction(CONFIG_PT_LED_GPIO, GPIO_MODE_OUTPUT);
    led_write(false);
#endif
    const esp_timer_create_args_t args = {.callback = led_tick, .name = "pt_led"};
    if (esp_timer_create(&args, &s_led_timer) == ESP_OK) {
        esp_timer_start_periodic(s_led_timer, TICK_MS * 1000);
    }
}

void pt_led_set(pt_led_state_t state)
{
    if (state != s_led) {
        s_led = state;
        /* Machine-readable for the HIL runner; also helps users with a serial console. */
        ESP_LOGI(TAG, "PT_LED %s", led_name(state));
    }
}

pt_led_state_t pt_led_get(void)
{
    return s_led;
}

void pt_led_blip(void)
{
    s_blip_ticks = 2;
}

/* ------------------------------------------------------------------------------------------ */

static pt_button_cb s_cb;

static bool button_down(void)
{
    if (s_sim_ms > 0) {
        return true;
    }
    return gpio_get_level(CONFIG_PT_BUTTON_GPIO) == 0;
}

static void button_task(void *arg)
{
    (void)arg;
    uint32_t held = 0;
    pt_led_state_t before = PT_LED_OFF;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(20));
        if (s_sim_ms > 0) {
            s_sim_ms = s_sim_ms > 20 ? s_sim_ms - 20 : 0; /* simulated press counts down */
        }
        if (button_down()) {
            if (held == 0) {
                before = pt_led_get();
                ESP_LOGI(TAG, "PT_BUTTON down");
            }
            held += 20;
            if (held >= RESET_MS) {
                pt_led_set(PT_LED_HOLD_RESET);
            } else if (held >= SETUP_MS) {
                pt_led_set(PT_LED_HOLD_SETUP);
            }
            continue;
        }
        if (held == 0) {
            continue;
        }
        ESP_LOGI(TAG, "PT_BUTTON up after %lu ms", (unsigned long)held);
        uint32_t h = held;
        held = 0;
        if (h >= RESET_MS) {
            if (s_cb) {
                s_cb(PT_BUTTON_RESET);
            }
        } else if (h >= SETUP_MS) {
            if (s_cb) {
                s_cb(PT_BUTTON_SETUP);
            }
        } else {
            pt_led_set(before);
        }
    }
}

esp_err_t pt_button_start(pt_button_cb cb)
{
    s_cb = cb;
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << CONFIG_PT_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&io);
    if (err != ESP_OK) {
        return err;
    }
    return xTaskCreate(button_task, "pt_button", 3072, NULL, 3, NULL) == pdPASS ? ESP_OK
                                                                                : ESP_ERR_NO_MEM;
}

void pt_button_simulate(uint32_t ms)
{
    s_sim_ms = ms;
}

# Always registered (Kconfig values are not known during requirement expansion); the source is
# compiled out with CONFIG_PT_MQTT=n.
idf_component_register(
    SRCS "pt_mqtt.c"
    INCLUDE_DIRS "include"
    REQUIRES pt_esp pt_core
    PRIV_REQUIRES mqtt mbedtls esp_timer)

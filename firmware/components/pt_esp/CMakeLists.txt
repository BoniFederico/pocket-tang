idf_component_register(
    SRCS "pt_store.c" "pt_worker.c" "pt_stats.c" "pt_wifi.c" "pt_httpd.c" "pt_console.c"
    INCLUDE_DIRS "include"
    REQUIRES pt_core esp_http_server esp_wifi esp_netif esp_event nvs_flash esp_timer
    PRIV_REQUIRES console lwip)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wshadow -Wvla)

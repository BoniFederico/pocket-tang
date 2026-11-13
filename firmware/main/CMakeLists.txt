idf_component_register(
    SRCS "main.c" "ui.c"
    INCLUDE_DIRS "."
    REQUIRES pt_core pt_esp esp_timer)

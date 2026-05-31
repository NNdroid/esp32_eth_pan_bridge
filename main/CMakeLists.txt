idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_eth esp_driver_gpio driver freertos log btstack esp_http_server
)
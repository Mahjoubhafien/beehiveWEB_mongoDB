#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_log.h"
#include "nvs_flash.h"

#define TAG "ESP_NOW_SENDER"

typedef struct __attribute__((packed)) {
    char sensor_id[12];
    float temperature;
    float humidity;
    float longitude;
    float latitude;
} sensor_data_t;

// Replace with your RECEIVER's MAC
uint8_t receiver_mac[] = {0x40, 0x4C, 0xCA, 0x55, 0xE5, 0x94};

void wifi_init() {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void espnow_init() {
    ESP_ERROR_CHECK(esp_now_init());

    esp_now_peer_info_t peerInfo = {
        .channel = 0,
        .ifidx = ESP_IF_WIFI_STA,
        .encrypt = false
    };
    memcpy(peerInfo.peer_addr, receiver_mac, 6);
    ESP_ERROR_CHECK(esp_now_add_peer(&peerInfo));
}

void send_data_task(void *pvParameter) {
    sensor_data_t sensor_data = {
        .temperature = 25.0f,
        .humidity = 60.0f,
        .longitude = -122.41f,
        .latitude = 37.77f
    };
    strcpy(sensor_data.sensor_id, "sensor-002");


    while (1) {
        ESP_LOGI(TAG, "Sending data to receiver...");
        esp_err_t result = esp_now_send(receiver_mac, (uint8_t *)&sensor_data, sizeof(sensor_data));

        if (result == ESP_OK) {
            ESP_LOGI(TAG, "Data sent successfully");
        } else {
            ESP_LOGE(TAG, "Failed to send data: %d", result);
        }

        sensor_data.temperature += 0.2f;
        sensor_data.humidity -= 0.2f;
        if (sensor_data.temperature > 30.0f) sensor_data.temperature = 25.0f;
        if (sensor_data.humidity < 55.0f) sensor_data.humidity = 60.0f;

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void app_main() {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init();
    espnow_init();
    xTaskCreate(send_data_task, "send_data_task", 4096, NULL, 5, NULL);
}

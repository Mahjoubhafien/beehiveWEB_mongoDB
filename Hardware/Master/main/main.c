#include "main.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "gps.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/unistd.h>

#define STORAGE_NAMESPACE "storage"

// QueueHandle_t dhtQueue;
QueueHandle_t gpsQueue;
// QueueHandle_t hx711Queue;
QueueHandle_t espnowQueue; // Add this with your other queue definitions
QueueHandle_t alertConfigQueue;

SemaphoreHandle_t sim800_uart_mutex = NULL;
TaskHandle_t smsTaskHandle = NULL; // real definition

// User Specific Variables
char ip_address[] = "apibee.seetechnology.ovh";
char *user_id = "68a5fc2cd787ed1a68e6c713";
char user_phone_number[20] = "+21693617570";
// uint32_t SIM_delay = 3600000; //1h
uint32_t SIM_delay = 1800000; // 30 minute
bool eco_mode = true;         // false = use vTaskDelay, true = use light sleep
typedef struct __attribute__((packed)) {
  char sensor_id[12];
  float temperature;
  float humidity;
  float longitude;
  float latitude;
} sensor_data_t;

// Correct callback signature for ESP-IDF v5.3.1
void espnow_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data,
                    int data_len) {
  if (data_len == sizeof(sensor_data_t)) {
    sensor_data_t received_data;
    memcpy(&received_data, data, sizeof(sensor_data_t));

    if (xQueueSend(espnowQueue, &received_data, pdMS_TO_TICKS(100)) != pdTRUE) {
      ESP_LOGE(TAG, "Failed to send data to queue (queue full?)");
    } else {
      ESP_LOGI(TAG,
               "received data from esp now | ID: %s | Temp: %.2f | Hum: %.2f",
               received_data.sensor_id, received_data.temperature,
               received_data.humidity);
    }
  } else {
    ESP_LOGE(TAG, "Data length mismatch: received %d bytes, expected %d",
             data_len, sizeof(sensor_data_t));
  }
}
void espnow_init() {
  ESP_ERROR_CHECK(esp_now_init());
  ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
}
void espnow_receiver_task(void *pvParameters) {
  while (1) {
    // Just keep the task running - all work is done in the callback
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
void wifi_init() {
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());
}

// UART config
void sim800_UART_init(void) {
  const uart_config_t uart_config = {.baud_rate = 9600,
                                     .data_bits = UART_DATA_8_BITS,
                                     .parity = UART_PARITY_DISABLE,
                                     .stop_bits = UART_STOP_BITS_1,
                                     .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};

  uart_driver_install(UART_PORT, BUF_SIZE * 2, 0, 0, NULL, 0);

  uart_param_config(UART_PORT, &uart_config);

  uart_set_pin(UART_PORT, TX_PIN, RX_PIN, UART_PIN_NO_CHANGE,
               UART_PIN_NO_CHANGE);
}

void GPS_UART_init(void) {
  const uart_config_t uart_config = {.baud_rate = 9600,
                                     .data_bits = UART_DATA_8_BITS,
                                     .parity = UART_PARITY_DISABLE,
                                     .stop_bits = UART_STOP_BITS_1,
                                     .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};

  uart_driver_install(GPS_UART_PORT, BUF_SIZE * 2, 0, 0, NULL, 0);

  uart_param_config(GPS_UART_PORT, &uart_config);

  uart_set_pin(GPS_UART_PORT, GPS_TXD_PIN, GPS_RXD_PIN, UART_PIN_NO_CHANGE,
               UART_PIN_NO_CHANGE);
}
void dht21_init(void) {
  // 1) Configure GPIO12 as open-drain, no internal pull-ups
  gpio_config_t io_conf = {.pin_bit_mask = 1ULL << DHT_GPIO,
                           .mode = GPIO_MODE_INPUT_OUTPUT_OD,
                           .pull_up_en = GPIO_PULLUP_DISABLE,
                           .pull_down_en = GPIO_PULLDOWN_DISABLE,
                           .intr_type = GPIO_INTR_DISABLE};
  gpio_config(&io_conf);

  // 2) Wait for sensor to power-up and stabilize
  ESP_LOGI("DHT21_Example", "Waiting for sensor to stabilize...");
  vTaskDelay(pdMS_TO_TICKS(2000));
}
// sim800c init need to be repeated 3 time to be init without error!
void sim800c_init(void) {

  // Wait for SIM800C boot
  sim800_send_command("AT+CFUN=1,1");
  vTaskDelay(pdMS_TO_TICKS(10000));

  ESP_LOGI("SIM_INIT", "=== SIM800C Initialization Sequence ===");

  sim800_send_command("AT");
  sim800_wait_response();

  // lock baud rate to 9600
  sim800_send_command("AT+IPR=9600");
  sim800_wait_response();

  sim800_send_command("AT+CPIN?");
  sim800_wait_response();

  sim800_send_command("AT+CSQ");
  sim800_wait_response();

  sim800_send_command("AT+CREG?");
  sim800_wait_response();

  sim800_send_command("AT+CGATT=1");
  sim800_wait_response();

  sim800_send_command("AT+SAPBR=3,1,\"Contype\",\"GPRS\"");
  sim800_wait_response();

  sim800_send_command("AT+SAPBR=3,1,\"APN\",\"internet.tn\"");
  sim800_wait_response();

  // Initialize the GPRS connection (activate the bearer profile and connect to
  // the network)
  sim800_send_command("AT+SAPBR=1,1"); // Activate bearer profile
  sim800_wait_response();

  sim800_send_command(
      "AT+SAPBR=2,1"); // Query bearer profile (check if connected)
  sim800_wait_response();

  // Initialize HTTP connection
  sim800_send_command("AT+HTTPINIT"); // Initialize HTTP service
  sim800_wait_response();

  // Set up the CID (context ID for the bearer profile)
  sim800_send_command("AT+HTTPPARA=\"CID\",1"); // Set CID to 1
  sim800_wait_response();

  // Set SMS text mode
  uart_write_bytes(UART_PORT, "AT+CMGF=1\r\n", strlen("AT+CMGF=1\r\n"));

  // Enable software-controlled sleep (no DTR needed)
  sim800_send_command("AT+CSCLK=2");
  sim800_wait_response();

  ESP_LOGI("SIM_INIT", "SIM800C Initialization Complete.");
}
// helper functions to save/load values in nvs
void save_ip_to_nvs(const char *ip) {
  nvs_handle_t nvs_handle;
  if (nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvs_handle) == ESP_OK) {
    nvs_set_str(nvs_handle, "ip_addr", ip);
    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
  }
}

void save_delay_to_nvs(uint32_t delay) {
  nvs_handle_t nvs_handle;
  if (nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvs_handle) == ESP_OK) {
    nvs_set_u32(nvs_handle, "sim_delay", delay);
    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
  }
}

void load_config_from_nvs() {
  nvs_handle_t nvs_handle;
  size_t required_size;
  if (nvs_open(STORAGE_NAMESPACE, NVS_READONLY, &nvs_handle) == ESP_OK) {

    // Load IP address
    required_size = sizeof(ip_address);
    if (nvs_get_str(nvs_handle, "ip_addr", ip_address, &required_size) !=
        ESP_OK) {
      strcpy(ip_address, "apibee.seetechnology.ovh"); // default
    }

    // Load SIM delay
    if (nvs_get_u32(nvs_handle, "sim_delay", &SIM_delay) != ESP_OK) {
      SIM_delay = 3600000; // default 1h
    }
    // Load user/admin phone number
    required_size = sizeof(user_phone_number);
    if (nvs_get_str(nvs_handle, "user_phone", user_phone_number,
                    &required_size) != ESP_OK) {
      strcpy(user_phone_number, "+21693617570"); // default phone number
    }
    nvs_close(nvs_handle);
  }
}
void save_user_phone_to_nvs(const char *phone) {
  nvs_handle_t nvs_handle;
  if (nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &nvs_handle) == ESP_OK) {
    nvs_set_str(nvs_handle, "user_phone", phone);
    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
  }
}

void load_user_phone_from_nvs() {
  nvs_handle_t nvs_handle;
  size_t required_size = sizeof(user_phone_number);

  if (nvs_open(STORAGE_NAMESPACE, NVS_READONLY, &nvs_handle) == ESP_OK) {
    if (nvs_get_str(nvs_handle, "user_phone", user_phone_number,
                    &required_size) != ESP_OK) {
      strcpy(user_phone_number, "+21693617570"); // default fallback
    }
    nvs_close(nvs_handle);
  }
}
///////////////////////////////////////// Main APP
/////////////////////////////////////////////////
void app_main(void) {
  gpio_reset_pin(10);
  gpio_set_direction(10, GPIO_MODE_OUTPUT);

  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  // Load saved values
  load_config_from_nvs();
  ESP_LOGI("CONFIG", "Loaded IP: %s", ip_address);
  ESP_LOGI("CONFIG", "Loaded Delay: %" PRIu32, SIM_delay);
  ESP_LOGI("CONFIG", "Loaded number: %s", user_phone_number);

  // Create the queue with space for 5 SensorData_t elements
  // Create queues
  // dhtQueue = xQueueCreate(30, sizeof(DHTData_t));
  // gpsQueue = xQueueCreate(30, sizeof(GPSData_t));
  // hx711Queue = xQueueCreate(30, sizeof(HX711Data_t));
  // espnowQueue = xQueueCreate(30, sizeof(sensor_data_t)); // Buffer 10
  // messages
  alertConfigQueue = xQueueCreate(1, sizeof(AlertConfig_t));
  /*
    if (dhtQueue == NULL || gpsQueue == NULL || espnowQueue == NULL) {
      ESP_LOGE(TAG, "Queue creation failed");
      return;
    } // Initialize NVS*/
  sim800_uart_mutex = xSemaphoreCreateMutex();
  if (sim800_uart_mutex == NULL) {
    ESP_LOGE(TAG, "Failed to create SIM800 UART mutex");
    return;
  }

  ESP_ERROR_CHECK(nvs_flash_init());

  // Initialize WiFi and ESP-NOW
  wifi_init();
  espnow_init();

  //------------------------------>>>>> initialisation
  sim800_UART_init();
  
   GPS_UART_init(); 
  
  sim800c_init();
  dht21_init();
  myhx711_init();

  /////////////////////////////////////////////// Start tasks
  ///////////////////////////////////////

  // first 50 every 2s then the rest every 1H
  // xTaskCreate(dht_test, "dht21_task", 4096, NULL, 6, NULL);// !!!!DONT USE IT
  // I INTEGRATE IT IN SIM800c_task

  // first 30 every 2s then the rest every 1H
  // xTaskCreate(gps_task, "gps_task", 4096, NULL, 6, NULL); Dont use it , i
  // integrate it in the sim task

  // first 10 every 3s then the rest every 1H
  xTaskCreate(sim800c_task, "sim800c_task", 8192, NULL, 6, NULL);

  // Every 5s

  xTaskCreate(sms_control_task, "sms_control_task", 8192, NULL, 6,
              &smsTaskHandle);

  // xTaskCreate(espnow_receiver_task, "espnow_receiver_task", 4096, NULL,
  // 5,NULL);

  //  First 50 every 10s and the other every 50minute
  // xTaskCreate(hx711_task, "hx711_task", 8192, NULL, 6, NULL); // dont use it
  // !!!! i embedded it in sim task

  // every 10s
  // xTaskCreate(getWebServerData_task, "getWebServerData_task", 4096, NULL,
  // 6,NULL);//!!!!DONT USE IT I INTEGRATE IT IN SIM800c_task

  ESP_LOGI(TAG, "ESP-NOW Receiver initialized and waiting for data...");
}

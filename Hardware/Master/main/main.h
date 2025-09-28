/*
 * main.h
 *
 *  Created on: 8 Apr 2025
 *      Author: KURAPIKA
 */

#ifndef MAIN_MAIN_H_
#define MAIN_MAIN_H_
#include "dht22.h"
#include "esp_now.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "getWebServerData.h"
#include "gps.h"
#include "myHX711.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sim800c.h"
#include "smsControl.h"
#include <stdint.h>

#define WIFI_SSID "TOPNET_3D78"
#define WIFI_PASSWORD "Hafiene2025"
#define WIFI_CONNECTED_BIT BIT0
#define IP_ADDR_MAX_LEN 32
#define DHT_GPIO GPIO_NUM_12
#define DHT_TYPE DHT_TYPE_AM2301

extern SemaphoreHandle_t sim800_uart_mutex;
extern char ip_address[IP_ADDR_MAX_LEN];
extern char *user_id;
extern char user_phone_number[20];
extern bool eco_mode;
extern uint32_t SIM_delay;
extern TaskHandle_t smsTaskHandle;

typedef struct {
  float temperature;
  float humidity;
} DHTData_t;

typedef struct {
  float latitude;
  float longitude;
} GPSData_t;
typedef struct {
  float weight;
} HX711Data_t;

// In your main.h or at the top of your file
typedef struct {
  char sensor_id[12];
  float temperature;
  float humidity;
  float longitude;
  float latitude;
} ESPNowData_t;

typedef struct {
  int min_temp;
  int max_temp;
  int min_humidity;
  int max_humidity;
  int min_weight;
  int max_weight;
  bool is_alerts_on;
  bool is_eco_mode_on;
  double latitude;
  double longitude;
} AlertConfig_t;

extern QueueHandle_t dhtQueue;
extern QueueHandle_t gpsQueue;
extern QueueHandle_t hx711Queue;
extern QueueHandle_t espnowQueue;
extern QueueHandle_t alertConfigQueue; // Declare if in a header

void save_ip_to_nvs(const char *ip);
void save_delay_to_nvs(uint32_t delay);
void load_config_from_nvs();
void load_user_phone_from_nvs();
void save_user_phone_to_nvs(const char *phone);
void sim800c_init(void);
#endif /* MAIN_MAIN_H_ */

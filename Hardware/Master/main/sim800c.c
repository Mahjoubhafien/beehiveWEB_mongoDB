/*
 * sim800c.c
 *
 *  Created on: 8 Apr 2025
 *      Author: KURAPIKA
 */
#include "sim800c.h"
#include "dht.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_sleep.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "main.h"
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <sys/unistd.h>
#define LED_INDICATOR GPIO_NUM_10

// SMS Alerts Related Parameters
bool isAlertsON = true;
bool sim800Reset = false;
bool sim800_init = false;
bool isAlertStopLocal = false;
bool isAlertStopRemote = false;
int alertCounterLocal = 0;
int alertCounterRemote = 0;
float MIN_TEMP = 32;
float MAX_TEMP = 36;
float MIN_HUMIDITY = 50;
float MAX_HUMIDITY = 70;
float temperature = 0.0f;
float humidity = 0.0f;

static const char *SIM_TAG = "SIM800C";

TaskHandle_t sim800_task_handle = NULL;

uint8_t error_count = 0;
uint8_t max_error_count = 5;

float sim800_battery_voltage = 0.0;
float weight = 0.0;
float mylatitude = 0.0;
float mylongitude = 0.0;

DHTData_t latestDHT = {0}; // Initialize to avoid garbage
GPSData_t latestGPS = {0};
ESPNowData_t latestESPNow = {0};
// HX711Data_t latestHX711 = {0};

void sim800_send_sms(const char *number, const char *message) {
  char buffer[128];

  // Prepare the CMGS command
  sprintf(buffer, "AT+CMGS=\"%s\"\r\n", number);
  uart_write_bytes(UART_PORT, buffer, strlen(buffer));
  vTaskDelay(pdMS_TO_TICKS(500)); // Wait for '>' prompt

  // Send the message body
  uart_write_bytes(UART_PORT, message, strlen(message));
  uart_write_bytes(UART_PORT, "\x1A", 1); // CTRL+Z to send
  vTaskDelay(pdMS_TO_TICKS(5000));        // Wait for sending to complete

  ESP_LOGI(SIM_TAG, "SMS sent to %s: %s", number, message);
}

void sim800_send_command(const char *cmd) {
  uart_flush(UART_PORT);
  uart_write_bytes(UART_PORT, cmd, strlen(cmd));
  uart_write_bytes(UART_PORT, "\r\n", 2); // CR+LF
}

void sim800_send_raw(const char *data) {
  uart_write_bytes(UART_PORT, data, strlen(data));
  ESP_LOGI("SIM800C", "Sent raw data: %s", data);
}

void sim800_wait_response() {
  uint8_t data[BUF_SIZE];
  memset(data, 0, sizeof(data));

  int len = uart_read_bytes(UART_PORT, data, BUF_SIZE - 1,
                            pdMS_TO_TICKS(AT_CMD_TIMEOUT_MS));
  if (len > 0) {
    data[len] = '\0';
    if (strstr((char *)data, "ERROR") != NULL) {
      error_count++;
      ESP_LOGE(SIM_TAG, "Response Error:\n%s", (char *)data);
      ESP_LOGW(SIM_TAG, "Error Number %d", error_count);
      if (error_count >= max_error_count) {
        ESP_LOGI(SIM_TAG, "=== SIM800C Reset ===");
        error_count = 0;
        sim800Reset = true;
      }
    } else {
      ESP_LOGI(SIM_TAG, "Response:\n%s", (char *)data);
    }
  } else {
    ESP_LOGW(SIM_TAG, "No response or timeout");
  }
}
float get_sim800_battery_voltage() {
  const char *cmd = "AT+CBC";
  uint8_t data[BUF_SIZE] = {0};

  uart_flush(UART_PORT); // Clear UART buffer

  sim800_send_command("AT");
  sim800_wait_response();

  // Send command
  uart_write_bytes(UART_PORT, cmd, strlen(cmd));
  uart_write_bytes(UART_PORT, "\r\n", 2);

  // Read response
  int len = uart_read_bytes(UART_PORT, data, BUF_SIZE - 1, pdMS_TO_TICKS(1000));

  if (len > 0) {
    data[len] = '\0';

    char *cbc_line = strstr((char *)data, "+CBC:");
    if (cbc_line) {
      int bcs, bcl, voltage_mv;
      if (sscanf(cbc_line, "+CBC: %d,%d,%d", &bcs, &bcl, &voltage_mv) == 3) {
        return voltage_mv / 1000.0f; // Convert to volts
      }
    } else {
      ESP_LOGW("SIM800C", "No +CBC response found");
    }
  } else {
    ESP_LOGW("SIM800C", "No data or timeout reading +CBC response");
  }

  return -1.0f;
}
// === SIM800C Task ===
void sim800c_task(void *pvParameters) { sim800_http_post_task(); }
void sim800_http_post_task(void) {

  static int iteration_count = 0;

  while (1) {

    if (xSemaphoreTake(sim800_uart_mutex, portMAX_DELAY) == pdTRUE) {
      if (!sim800Reset) {

        if (sim800_init) {
          sim800_send_command("AT+CFUN=1"); // wake module without reboot
          vTaskDelay(pdMS_TO_TICKS(500));   // short delay to allow RF startup
          sim800_send_command("AT");        // check if awake
          sim800c_init();
        }

        sim800_battery_voltage = get_sim800_battery_voltage();
        dht21_task();
        hx711_task();
        gps_task(); 
        sim800c_get_sms_alerts_data();

        ///------------------------>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        /// END

        // Construct the JSON payload with all available data
        char json_payload[512]; // Increased size to accommodate all data
        snprintf(json_payload, sizeof(json_payload),
                 "{"
                 "\"local_sensor\":{"
                 "\"id\":\"sensor-001\","
                 "\"temperature\":%.2f,"
                 "\"humidity\":%.2f,"
                 "\"latitude\":%.6f,"
                 "\"longitude\":%.6f,"
                 "\"battery_voltage\":%.2f,"
                 "\"weight\":%.3f"
                 "},"
                 "\"remote_sensor\":{"
                 "\"id\":\"%s\","
                 "\"temperature\":%.2f,"
                 "\"humidity\":%.2f,"
                 "\"latitude\":%.6f,"
                 "\"longitude\":%.6f"
                 "}"
                 "}",
                 // Local sensor data
                 temperature, humidity, mylatitude, mylongitude,
                 sim800_battery_voltage,
                 weight, // <--- HX711 weight
                 // Remote sensor data
                 latestESPNow.sensor_id, latestESPNow.temperature,
                 latestESPNow.humidity, latestESPNow.latitude,
                 latestESPNow.longitude);
        AlertConfig_t active_config;
        if (xQueuePeek(alertConfigQueue, &active_config, pdMS_TO_TICKS(10)) ==
            pdPASS) { // Non-blocking read

          // === LOCAL SENSOR ALERT HANDLER ===
          if (active_config.is_alerts_on && !isAlertStopLocal) {
            char alert_msg[256];
            // === GPS MOVEMENT ALERT ===
            float lat_diff = fabs(mylatitude - active_config.latitude);
            float lon_diff = fabs(mylongitude - active_config.longitude);
            if ((lat_diff > GPS_MOVEMENT_THRESHOLD ||
                 lon_diff > GPS_MOVEMENT_THRESHOLD)) {
              char gps_alert_msg[256];
              snprintf(gps_alert_msg, sizeof(gps_alert_msg),
                       "MOVEMENT ALERT from sensor-001:\nNew Location: "
                       "https://maps.google.com/?q=%.6f,%.6f",
                       mylatitude, mylongitude);
              sim800_send_sms(user_phone_number, gps_alert_msg);

              // Optional: log or throttle alerts
              ESP_LOGI("SIM800C", "Movement alert sent due to GPS change");
              alertCounterLocal++;
            }

            if (temperature != 0 &&
                !(temperature <= active_config.max_temp &&
                  temperature >= active_config.min_temp) &&
                !0) {
              snprintf(alert_msg, sizeof(alert_msg),
                       "ALERT from sensor-001:\nTemperature outside safe "
                       "range: %.2f C\nLocation: "
                       "https://maps.google.com/?q=%.6f,%.6f",
                       temperature, mylatitude, mylongitude);
              sim800_send_sms(user_phone_number, alert_msg);
              alertCounterLocal++;
            } else if (humidity != 0 &&
                       !(humidity <= active_config.max_humidity &&
                         humidity >= active_config.min_humidity)) {
              snprintf(alert_msg, sizeof(alert_msg),
                       "ALERT from sensor-001:\nHumidity outside safe range: "
                       "%.2f%%\nLocation: https://maps.google.com/?q=%.6f,%.6f",
                       humidity, mylatitude, mylongitude);
              sim800_send_sms(user_phone_number, alert_msg);
              alertCounterLocal++;
            }

            if (alertCounterLocal >= 5) {
              ESP_LOGI("SIM800C", "Calling due to local sensor alert...");
              char call_cmd[64];
              snprintf(call_cmd, sizeof(call_cmd), "ATD%s;", user_phone_number);
              sim800_send_command(call_cmd);
              sim800_wait_response();
              alertCounterLocal = 0;
              isAlertStopLocal = true;
            }
          }

          // === REMOTE SENSOR ALERT HANDLER ===
          if (active_config.is_alerts_on && !isAlertStopRemote) {
            char alert_msg[256];

            if (latestESPNow.temperature != 0 &&
                !(latestESPNow.temperature <= active_config.max_temp &&
                  latestESPNow.temperature >= active_config.min_temp)) {
              snprintf(alert_msg, sizeof(alert_msg),
                       "ALERT from %s:\nHigh Temp: %.2f C\nLocation: "
                       "https://maps.google.com/?q=%.6f,%.6f",
                       latestESPNow.sensor_id, latestESPNow.temperature,
                       latestESPNow.latitude, latestESPNow.longitude);
              sim800_send_sms(user_phone_number, alert_msg);
              alertCounterRemote++;
            } else if (latestESPNow.humidity != 0 &&
                       !(latestESPNow.humidity <= active_config.max_humidity &&
                         latestESPNow.humidity >= active_config.min_humidity)) {
              snprintf(alert_msg, sizeof(alert_msg),
                       "ALERT from %s:\nHigh Humidity: %.2f%%\nLocation: "
                       "https://maps.google.com/?q=%.6f,%.6f",
                       latestESPNow.sensor_id, latestESPNow.humidity,
                       latestESPNow.latitude, latestESPNow.longitude);
              sim800_send_sms(user_phone_number, alert_msg);
              alertCounterRemote++;
            }

            if (alertCounterRemote >= 5) {
              ESP_LOGI("SIM800C", "Calling due to remote sensor alert...");
              char call_cmd[64];
              snprintf(call_cmd, sizeof(call_cmd), "ATD%s;", user_phone_number);
              sim800_send_command(call_cmd);
              sim800_wait_response();
              alertCounterRemote = 0;
              isAlertStopRemote = true;
            }
          }

          // === Reset LOCAL alert if safe ===
          if ((temperature <= active_config.max_temp &&
               temperature >= active_config.min_temp) &&
              (humidity <= active_config.max_humidity &&
               humidity >= active_config.min_humidity)) {
            isAlertStopLocal = false;
            alertCounterLocal = 0;
          }

          // === Reset REMOTE alert if safe ===
          if ((latestESPNow.temperature <= active_config.max_temp &&
               latestESPNow.temperature >= active_config.min_temp) &&
              (latestESPNow.humidity <= active_config.max_humidity &&
               latestESPNow.humidity >= active_config.min_humidity)) {
            isAlertStopRemote = false;
            alertCounterRemote = 0;
          }

        } else {
          ESP_LOGW("ALERT", "No configuration available in alertConfigQueue.");
        }

        ESP_LOGI("HTTP POST", "Sending JSON: %s", json_payload);
        ESP_LOGI("SIM800C", "=== Starting HTTP POST Task ===");
        gpio_set_level(LED_INDICATOR, 1); // LED on for Step 1

        char command[256];

        sim800_send_command("AT+HTTPINIT"); // Initialize HTTP service
        sim800_wait_response();

        // build the command dynamically
        snprintf(command, sizeof(command),
                 "AT+HTTPPARA=\"URL\",\"http://%s/temphum\"", ip_address);

        // send it
        sim800_send_command(command);
        sim800_wait_response();

        // 2. (Optional) Ensure content-type is JSON
        sim800_send_command("AT+HTTPPARA=\"CONTENT\",\"application/json\"");
        sim800_wait_response();

        // 3. Prepare to send data
        char cmd[32];
        sprintf(cmd, "AT+HTTPDATA=%d,10000", strlen(json_payload));
        sim800_send_command(cmd);
        sim800_wait_response(); // Wait for DOWNLOAD

        // 4. Send the JSON body
        sim800_send_raw(json_payload);
        sim800_wait_response();

        // 5. Trigger POST action
        sim800_send_command("AT+HTTPACTION=1");
        sim800_wait_response(); // Will return: +HTTPACTION: 1,200,<data_len>

        // 6. Read server response
        sim800_send_command("AT+HTTPREAD");
        sim800_wait_response();

        ESP_LOGI("SIM800C", "=== HTTP POST Done ===");
        gpio_set_level(LED_INDICATOR, 0); // LED on for Step 1

      } else {
        ESP_LOGI(SIM_TAG, "=== Start SIM800C Reset ===");
        esp_restart();
      }
      xSemaphoreGive(sim800_uart_mutex); // release after done

    } else {

      vTaskDelay(pdMS_TO_TICKS(1000));
    }
    // === Delayed Execution Based on Iteration ===
    if (iteration_count < 10) {
      if (eco_mode) {
        sim800_init = false;
        iteration_count++;
        esp_sleep_enable_timer_wakeup(3 * 1000000ULL); // 3 sec
        esp_light_sleep_start();
      } else {
        vTaskDelay(pdMS_TO_TICKS(3000));
        iteration_count++;
      }
    } else {
      if (eco_mode) {
        sim800_init = true;
        // Put SIM800C to sleep before MCU sleep
        sim800_send_command(
            "AT+CFUN=0\r"); // AT+CFUN=0：  Minimum functionality (disable RF
                            // function). 0.6ma
        vTaskDelay(pdMS_TO_TICKS(200)); // Small delay to ensure SIM sleeps

        esp_sleep_enable_timer_wakeup(SIM_delay * 1000ULL); // SIM_delay in ms
        esp_light_sleep_start();
      } else {
        vTaskDelay(pdMS_TO_TICKS(SIM_delay)); // ms
      }
    }
  }
}
void dht21_task(void) {
  esp_err_t res =
      dht_read_float_data(DHT_TYPE, DHT_GPIO, &humidity, &temperature);
  if (res == ESP_OK) {
    ESP_LOGI("DHT21_Example", "Humidity: %.1f %%  Temperature: %.1f C",
             humidity, temperature);
  } else {
    ESP_LOGE("DHT21_Example", "Failed to read from DHT sensor: %s",
             esp_err_to_name(res));
  }
}
void parse_alert_config(const char *json, AlertConfig_t *config) {
  char alerts_state[6] = {0};

  sscanf(json,
         "{\"MIN_TEMP\":%d,\"MAX_TEMP\":%d,\"MIN_HUMIDITY\":%d,\"MAX_"
         "HUMIDITY\":%d,"
         "\"MIN_WEIGHT\":%d,\"MAX_WEIGHT\":%d,\"isAlertsON\":%5[^,],"
         "\"REFERENCE_LATITUDE\":%lf,\"REFERENCE_LONGITUDE\":%lf}",
         &config->min_temp, &config->max_temp, &config->min_humidity,
         &config->max_humidity, &config->min_weight, &config->max_weight,
         alerts_state, &config->latitude, &config->longitude);

  config->is_alerts_on = (strstr(alerts_state, "true") != NULL);
}
void sim800_wait_response_get(char *out_buffer, size_t max_len) {
  // Read response into buffer (this depends on your existing UART logic)
  int len = uart_read_bytes(UART_PORT, (uint8_t *)out_buffer, max_len,
                            pdMS_TO_TICKS(3000));
  if (len > 0) {
    out_buffer[len] = '\0'; // Null-terminate
    ESP_LOGI("SIM800_RESPONSE", "%s", out_buffer);
  } else {
    out_buffer[0] = '\0';
  }
}

void sim800c_get_sms_alerts_data(void) {
  char response_buf[256];
  AlertConfig_t new_config;

  char command[256];

  ESP_LOGI("SIM800C", "=== Starting HTTP GET SMS ALerts Configuration ===");

  snprintf(command, sizeof(command),
           "AT+HTTPPARA=\"URL\",\"http://%s/api/"
           "public_alert-config?user_id=%s\"",
           ip_address, user_id);

  sim800_send_command(command);
  sim800_wait_response();

  // Trigger the HTTP GET action
  sim800_send_command("AT+HTTPACTION=0"); // 0 indicates a GET request
  sim800_wait_response();

  // Terminate the HTTP session (clean up resources)
  // sim800_send_command("AT+HTTPTERM");  // Terminate HTTP service
  // sim800_wait_response();

  // Read server response (you can print this for debugging)
  sim800_send_command("AT+HTTPREAD"); // Read the server's response
  sim800_wait_response_get(response_buf, sizeof(response_buf)); // ✅ FIXED

  char *json_start = strchr(response_buf, '{');
  if (json_start) {
    parse_alert_config(json_start, &new_config);

    xQueueOverwrite(alertConfigQueue, &new_config);

    ESP_LOGI("CONFIG",
             "Parsed Config: TEMP [%d-%d], HUM [%d-%d], ALERTS: %s,GPS REF: "
             "[%.6f, %.6f]",
             new_config.min_temp, new_config.max_temp, new_config.min_humidity,
             new_config.max_humidity, new_config.is_alerts_on ? "ON" : "OFF",
             new_config.latitude, new_config.longitude);
    // try to manipulate the eco_mode using another way
    if (new_config.max_weight > 100) {
      vTaskResume(smsTaskHandle); // allow it to run
      eco_mode = false;
    } else {
      vTaskSuspend(smsTaskHandle); // stop SMS task in eco mode
      eco_mode = true;
    }

  } else {
    ESP_LOGW("SIM800C", "Failed to find JSON in response");
  }

  sim800_send_command("AT+HTTPTERM"); // Terminate HTTP service
  sim800_wait_response();

  ESP_LOGI("SIM800C", "=== HTTP GET SMS ALerts Configuration Done ===");
  vTaskDelay(pdMS_TO_TICKS(2000));
}

/*
void sim800_http_get_task(void) {
  ESP_LOGI("SIM800C", "=== Starting HTTP GET Task ===");

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

  // Set the URL for the HTTP GET request
  sim800_send_command("AT+HTTPPARA=\"URL\",\"http://"
                      "jsonplaceholder.typicode.com/posts/1\""); // Set the GET
                                                                 // URL to
                                                                 // httpbin.org
  sim800_wait_response();

  // Trigger the HTTP GET action
  sim800_send_command("AT+HTTPACTION=0"); // 0 indicates a GET request
  sim800_wait_response(); // Wait for response, typically HTTP status code,
                          // e.g., +HTTPACTION: 0,200,<data_length>

  // Terminate the HTTP session (clean up resources)
  // sim800_send_command("AT+HTTPTERM");  // Terminate HTTP service
  // sim800_wait_response();

  // Read server response (you can print this for debugging)
  sim800_send_command("AT+HTTPREAD"); // Read the server's response
  sim800_wait_response();

  // Deactivate the bearer profile (optional but recommended to release
  // resources)
  // sim800_send_command("AT+SAPBR=0,1");  // Deactivate bearer profile
  // sim800_wait_response();

  ESP_LOGI("SIM800C", "=== HTTP GET Done ===");
}*/
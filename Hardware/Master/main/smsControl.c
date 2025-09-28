/*
 * smsControl.c
 *
 *  Created on: 16 Jun 2025
 *      Author: KURAPIKA
 */

#include "smsControl.h"
#include "cJSON.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_sleep.h"
#include "main.h" // UART_PORT, sim800_uart_mutex, etc.
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#define TAG_SMS "SMS_CTRL"

void sms_control_task(void *pvParameters) {

  uint8_t rx_buffer[512];
  int total_len = 0, len = 0; // Declare here
  sim800_send_command("AT+CMGDA=\"DEL ALL\"");
  sim800_wait_response();

  while (1) {
    // char ip_address[] = "102.159.90.106";
    // char *user_id = "68629553a6d3d20bcdd52efa";
    if (xSemaphoreTake(sim800_uart_mutex, portMAX_DELAY) == pdTRUE) {

      // Delete all message if memory full
      /*
            sim800_send_command("AT+CMGDA=\"DEL ALL\"");
            sim800_wait_response();
      */
      // Request all messages (use "REC UNREAD" later)

      uart_write_bytes(UART_PORT, "AT+CMGL=\"REC UNREAD\"\r\n",
                       strlen("AT+CMGL=\"REC UNREAD\"\r\n"));
      // Wait longer for response (1 second)
      vTaskDelay(pdMS_TO_TICKS(1000));

      // Read response
      total_len = 0; // reset for each loop
      do {
        len = uart_read_bytes(UART_PORT, rx_buffer + total_len,
                              sizeof(rx_buffer) - 1 - total_len,
                              pdMS_TO_TICKS(300));
        if (len > 0)
          total_len += len;
      } while (len > 0 && total_len < sizeof(rx_buffer) - 1);

      rx_buffer[total_len] = '\0';

      ESP_LOGI(TAG_SMS, "Len = %d", total_len);
      ESP_LOGI(TAG_SMS, "RAW SMS:\n%s", rx_buffer);

      // Parse line-by-line
      char *line = strtok((char *)rx_buffer, "\r\n");
      while (line != NULL) {
        if (strstr(line, "+CMGL:")) {
          // Parse the index and number
          int index = 0;
          char number[32] = {0};

          if (sscanf(line, "+CMGL: %d,\"REC READ\",\"%31[^\"]", &index,
                     number) != 2) {
            // Try REC UNREAD if needed
            sscanf(line, "+CMGL: %d,\"REC UNREAD\",\"%31[^\"]", &index, number);
          }

          // Get next line (message body)
          char *body = strtok(NULL, "\r\n");

          //////////////////// Restart ESP /////////////
          if (strcasecmp(body, "Admin Restart") == 0) {
            ESP_LOGW(TAG_SMS, "Admin command received: restarting...");
            sim800_send_sms(number, "The System is restarting by admin!");
            vTaskDelay(pdMS_TO_TICKS(2000)); // allow SMS to finish
            esp_restart();
            /////////////////// IP Configuration //////////////////
          } else if (strncasecmp(body, "Admin ip: ", 10) == 0) {
            // the SMS starts with "Admin "
            const char *new_ip =
                body + 10;             // points to the next part after "Admin "
            if (strlen(new_ip) < 32) { // some sanity check
              strncpy(ip_address, new_ip, sizeof(ip_address) - 1);
              ip_address[sizeof(ip_address) - 1] = '\0';
              save_ip_to_nvs(ip_address); // save to nvs
              ESP_LOGW(TAG_SMS, "Admin changed IP to: %s", ip_address);
              sim800_send_sms(number, "IP Address updated successfully!");
            } else {
              sim800_send_sms(number, "IP address too long");
            }

          }
          ///////////////////// SIM delay configuration //////////////////
          else if (strncasecmp(body, "delay_ms:", 9) == 0) {
            const char *delay_str = body + 9;     // Skip "delay_ms:"
            uint32_t delay_val = atoi(delay_str); // Convert string to integer

            if (delay_val > 0 &&
                delay_val < 86400000) { // sanity check: less than 24 hours
              SIM_delay = delay_val;
              save_delay_to_nvs(SIM_delay); // save to nvs
              ESP_LOGW(TAG_SMS, "Delay updated to: %" PRIu32 " ms", SIM_delay);
              sim800_send_sms(number, "Delay updated successfully!");
            } else {
              sim800_send_sms(number, "Invalid delay value");
            }
            //////////// Phone number configuration //////////
          } else if (strncasecmp(body, "Admin number:", 13) == 0) {
            const char *new_number = body + 13;
            if (strlen(new_number) < sizeof(user_phone_number)) {
              strncpy(user_phone_number, new_number,
                      sizeof(user_phone_number) - 1);
              user_phone_number[sizeof(user_phone_number) - 1] = '\0';
              save_user_phone_to_nvs(user_phone_number);
              ESP_LOGW(TAG_SMS, "User number updated to: %s",
                       user_phone_number);
              sim800_send_sms(number, "Phone number updated successfully!");
            } else {
              sim800_send_sms(number, "Phone number too long");
            }
          } else if (body != NULL && index > 0 &&
                     strcasecmp(body, "Admin Restart") != 0 &&
                     (strncasecmp(body, "Admin ip_address", 6) != 0)) {
            ESP_LOGI(TAG_SMS, "SMS from %s: %s", number, body);

            char url[256];
            snprintf(url, sizeof(url),
                     "http://%s/api/"
                     "public_get_sensor_data?user_id=%s&sensor_id=%s",
                     ip_address, user_id, body);

            char cmd[300];
            snprintf(cmd, sizeof(cmd), "AT+HTTPPARA=\"URL\",\"%s\"", url);

            sim800_send_command(cmd);
            sim800_wait_response();
            sim800_send_command("AT+HTTPACTION=0");
            sim800_wait_response();

            sim800_send_command("AT+HTTPREAD");

            uint8_t http_resp[512];
            int http_len = 0;
            int read_len = 0;
            do {
              read_len = uart_read_bytes(UART_PORT, http_resp + http_len,
                                         sizeof(http_resp) - 1 - http_len,
                                         pdMS_TO_TICKS(500));
              if (read_len > 0)
                http_len += read_len;
            } while (read_len > 0 && http_len < sizeof(http_resp) - 1);
            http_resp[http_len] = '\0';

            ESP_LOGI(TAG_SMS, "HTTP Response: %s", http_resp);

            // Extract JSON from HTTP response
            char *json_start = strchr((char *)http_resp, '{');
            char *json_end = strrchr((char *)http_resp, '}');

            if (json_start != NULL && json_end != NULL &&
                json_end > json_start) {
              size_t json_len = json_end - json_start + 1;
              char json_only[512];
              if (json_len >= sizeof(json_only))
                json_len = sizeof(json_only) - 1;
              memcpy(json_only, json_start, json_len);
              json_only[json_len] = '\0';

              cJSON *root = cJSON_Parse(json_only);
              if (root == NULL) {
                ESP_LOGE(TAG_SMS, "Failed to parse JSON");
              } else {
                // char delete_cmd[32];
                /*
                // delete last sms
                snprintf(delete_cmd, sizeof(delete_cmd), "AT+CMGD=%d", index);
                sim800_send_command(delete_cmd);
                sim800_wait_response();
                                */
                // delete all sms
                sim800_send_command("AT+CMGDA=\"DEL ALL\"");
                sim800_wait_response();

                // Check if JSON has "data" object or not
                cJSON *data = cJSON_GetObjectItem(root, "data");
                if (!data)
                  data = root;

                const cJSON *sensor_id = cJSON_GetObjectItem(data, "sensor_id");
                const cJSON *temperature =
                    cJSON_GetObjectItem(data, "temperature");
                const cJSON *humidity = cJSON_GetObjectItem(data, "humidity");
                const cJSON *latitude = cJSON_GetObjectItem(data, "latitude");
                const cJSON *longitude = cJSON_GetObjectItem(data, "longitude");
                const cJSON *weight = cJSON_GetObjectItem(data, "weight");

                char sms_msg[300];
                snprintf(
                    sms_msg, sizeof(sms_msg),
                    "Sensor: %s\n"
                    "Temp: %.1f C\n"
                    "Humidity: %.1f%%\n"
                    "Weight: %s Kg\n"
                    "Map: https://maps.google.com/?q=%.6f,%.6f",
                    sensor_id && sensor_id->valuestring
                        ? sensor_id->valuestring
                        : "Sensor not found for this user",
                    temperature && cJSON_IsNumber(temperature)
                        ? temperature->valuedouble
                        : 0.0,
                    humidity && cJSON_IsNumber(humidity) ? humidity->valuedouble
                                                         : 0.0,
                    weight && weight->valuestring ? weight->valuestring : "N/A",
                    latitude && cJSON_IsNumber(latitude) ? latitude->valuedouble
                                                         : 0.0,
                    longitude && cJSON_IsNumber(longitude)
                        ? longitude->valuedouble
                        : 0.0);

                cJSON_Delete(root);

                // Send SMS with formatted info
                sim800_send_sms(user_phone_number, sms_msg);
              }
            } else {
              ESP_LOGE(TAG_SMS, "Invalid JSON boundaries");
              sim800_send_sms(user_phone_number, "Server Busy Please Retry");
            }
          }
        }
        line = strtok(NULL, "\r\n");
      }
      xSemaphoreGive(sim800_uart_mutex); // release after done
      vTaskDelay(pdMS_TO_TICKS(5000));   // Retry if mutex unavailable
                                         /*
                                               esp_sleep_enable_timer_wakeup(3 * 1000000ULL); // 5 seconds
                                                         esp_light_sleep_start();
                                         */
    } else {
      vTaskDelay(pdMS_TO_TICKS(1000)); // Retry if mutex unavailable
                                       // mybe send sms say the sim is bussy
    }
  }
}
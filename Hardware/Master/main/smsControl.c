/*
 * smsControl.c
 *
 *  Created on: 16 Jun 2025
 *      Author: KURAPIKA
 */

#include "smsControl.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "cJSON.h"
#include <stdint.h>
#include <string.h>
#include "main.h"  // UART_PORT, sim800_uart_mutex, etc.

#define TAG_SMS "SMS_CTRL"

void sms_control_task(void *pvParameters) {

    uint8_t rx_buffer[512];
    int total_len = 0, len = 0;  // Declare here

    while (1) {
				//char ip_address[] = "102.159.90.106";
				int user_id = 1;
			  if (xSemaphoreTake(sim800_uart_mutex, portMAX_DELAY) == pdTRUE) {
				  
				//Delete all message if memory full  
			/*	  
   			sim800_send_command("AT+CMGDA=\"DEL ALL\"");
    		sim800_wait_response();
			*/
			
			
			
            // Request all messages (use "REC UNREAD" later)
			uart_write_bytes(UART_PORT, "AT+CMGL=\"REC UNREAD\"\r\n", strlen("AT+CMGL=\"REC UNREAD\"\r\n"));
            vTaskDelay(pdMS_TO_TICKS(500));  // Wait for SIM800C to respond

            // Read response
             total_len = 0; // reset for each loop
            do {
                len = uart_read_bytes(UART_PORT, rx_buffer + total_len,
                                      sizeof(rx_buffer) - 1 - total_len, pdMS_TO_TICKS(300));
                if (len > 0) total_len += len;
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

                if (sscanf(line, "+CMGL: %d,\"REC READ\",\"%31[^\"]", &index, number) != 2) {
                    // Try REC UNREAD if needed
                    sscanf(line, "+CMGL: %d,\"REC UNREAD\",\"%31[^\"]", &index, number);
                }

                // Get next line (message body)
                char *body = strtok(NULL, "\r\n");
                
                //Restart ESP 
                if (strcasecmp(body, "Admin Restart") == 0) {
    ESP_LOGW(TAG_SMS, "Admin command received: restarting...");
    sim800_send_sms(number, "The System is restarting by admin!");
    vTaskDelay(pdMS_TO_TICKS(2000)); // allow SMS to finish
    esp_restart();
}else if (strncasecmp(body, "Admin ip: ", 10) == 0) {
    // the SMS starts with "Admin "
    const char *new_ip = body + 10; // points to the next part after "Admin "
    if (strlen(new_ip) < 32) { // some sanity check
        strncpy(ip_address, new_ip, sizeof(ip_address) - 1);
        ip_address[sizeof(ip_address) - 1] = '\0'; // null-terminate
        ESP_LOGW(TAG_SMS, "Admin changed IP to: %s", ip_address);
        sim800_send_sms(number, "IP Address updated successfully!");
    } else {
        sim800_send_sms(number, "IP address too long");
    }
}
                else if (body != NULL && index > 0 && strcasecmp(body, "Admin Restart") != 0 && (strncasecmp(body, "Admin ip_address", 6) != 0)) {
                    ESP_LOGI(TAG_SMS, "SMS from %s: %s", number, body);

					char url[256];
					snprintf(url, sizeof(url),
   					 "http://%s:5000/api/public_get_sensor_data?user_id=%d&sensor_id=%s",
   						 ip_address, user_id, body);

						char cmd[300];
						snprintf(cmd, sizeof(cmd),
  						  "AT+HTTPPARA=\"URL\",\"%s\"", url);

						sim800_send_command(cmd);
						sim800_wait_response();
                        sim800_send_command("AT+HTTPACTION=0");
                        sim800_wait_response();

                        sim800_send_command("AT+HTTPREAD");

                        uint8_t http_resp[512];
                        int http_len = 0;
                        int read_len = 0;
                        do {
                            read_len = uart_read_bytes(UART_PORT, http_resp + http_len, sizeof(http_resp) - 1 - http_len, pdMS_TO_TICKS(500));
                            if (read_len > 0) http_len += read_len;
                        } while (read_len > 0 && http_len < sizeof(http_resp) - 1);
                        http_resp[http_len] = '\0';

                        ESP_LOGI(TAG_SMS, "HTTP Response: %s", http_resp);

                        // Extract JSON from HTTP response
                        char *json_start = strchr((char *)http_resp, '{');
                        char *json_end = strrchr((char *)http_resp, '}');

                        if (json_start != NULL && json_end != NULL && json_end > json_start) {
                            size_t json_len = json_end - json_start + 1;
                            char json_only[512];
                            if (json_len >= sizeof(json_only)) json_len = sizeof(json_only) - 1;
                            memcpy(json_only, json_start, json_len);
                            json_only[json_len] = '\0';


                            cJSON *root = cJSON_Parse(json_only);
                            if (root == NULL) {
                                ESP_LOGE(TAG_SMS, "Failed to parse JSON");
                            } else {
								 char delete_cmd[32];
                                //delete last sms
								snprintf(delete_cmd, sizeof(delete_cmd), "AT+CMGD=%d", index);
								sim800_send_command(delete_cmd);
								sim800_wait_response();

                                // Check if JSON has "data" object or not
                                cJSON *data = cJSON_GetObjectItem(root, "data");
                                if (!data) data = root;

                                const cJSON *sensor_id = cJSON_GetObjectItem(data, "sensor_id");
                                const cJSON *temperature = cJSON_GetObjectItem(data, "temperature");
                                const cJSON *humidity = cJSON_GetObjectItem(data, "humidity");
                                const cJSON *latitude = cJSON_GetObjectItem(data, "latitude");
                                const cJSON *longitude = cJSON_GetObjectItem(data, "longitude");
                                const cJSON *weight = cJSON_GetObjectItem(data, "weight");

                                char sms_msg[300];
                                snprintf(sms_msg, sizeof(sms_msg),
                                    "Sensor: %s\n"
                                    "Temp: %s C\n"
                                    "Humidity: %s%%\n"
                                    "Weight: %s Kg\n"
                                    "Map: https://maps.google.com/?q=%s,%s",
                                    sensor_id && sensor_id->valuestring ? sensor_id->valuestring : "Sensor not found for this user",
                                    temperature && temperature->valuestring ? temperature->valuestring : "N/A",
                                    humidity && humidity->valuestring ? humidity->valuestring : "N/A",
                                    weight && weight->valuestring ? weight->valuestring : "N/A",
                                    latitude && latitude->valuestring ? latitude->valuestring : "0",
                                    longitude && longitude->valuestring ? longitude->valuestring : "0"
                                );

                                cJSON_Delete(root);

                                // Send SMS with formatted info
                                char cmgs_cmd[64];
                                snprintf(cmgs_cmd, sizeof(cmgs_cmd), "AT+CMGS=\"%s\"\r\n", number);
                                sim800_send_command(cmgs_cmd);
                                vTaskDelay(pdMS_TO_TICKS(100)); // wait for '>' prompt

                                uart_write_bytes(UART_PORT, sms_msg, strlen(sms_msg));
                                uint8_t ctrl_z = 26;
                                uart_write_bytes(UART_PORT, (const char *)&ctrl_z, 1);

                                ESP_LOGI(TAG_SMS, "Sent formatted SMS to %s", number);

                            }
                        } else {
                            ESP_LOGE(TAG_SMS, "Invalid JSON boundaries");
                        }
                    }
                }
                line = strtok(NULL, "\r\n");
            }
	    	xSemaphoreGive(sim800_uart_mutex); // release after done
            vTaskDelay(pdMS_TO_TICKS(5000));  // Poll every 10 seconds
        } else{
			vTaskDelay(pdMS_TO_TICKS(1000)); // Retry if mutex unavailable
				//mybe send sms say the sim is bussy

    
}
}}
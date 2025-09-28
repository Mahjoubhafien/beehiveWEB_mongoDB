/*
 * smsControl.h
 *
 *  Created on: 16 Jun 2025
 *      Author: KURAPIKA
 */

#ifndef MAIN_SMSCONTROL_H_
#define MAIN_SMSCONTROL_H_

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#define RI_GPIO GPIO_NUM_4 // SIM800C RI connected here

void sms_control_task(void *pvParameters); // Declare the task function

#endif /* MAIN_SMSCONTROL_H_ */

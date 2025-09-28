/*
 * HX711.h
 *
 *  Created on: 16 Apr 2025
 *      Author: KURAPIKA
 */

#ifndef MAIN_MYHX711_H_
#define MAIN_MYHX711_H_

// Define HX711 pins
#include <stdint.h>
// Tag for logging

// void hx711_task(void *pvParameter);
void hx711_task(void);
void myhx711_init(void);
extern float weight;

#endif /* MAIN_MYHX711_H_ */

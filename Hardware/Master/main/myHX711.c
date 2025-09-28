#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hx711.h"
#include "main.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *hx711TAG = "HX711_APP";
#define LED_INDICATOR GPIO_NUM_10

static hx711_t hx711;

/* === Calibration config === */
#define REF_WEIGHT_G                                                           \
  500.0f // set this to your calibration mass in grams (e.g., 500g, 1000g)
#define TARE_SAMPLES 30
#define CAL_SAMPLES 30
#define RUN_SAMPLES 10

/* === NVS keys === */
#define NVS_NAMESPACE "hx711"
#define NVS_KEY_OFFSET "offset"
#define NVS_KEY_SCALE "cpg" // counts per gram

#define LED GPIO_NUM_8
#define BOOT_BTN GPIO_NUM_9

/* === Current calibration (RAM) === */
static int32_t g_offset = 0;           // raw counts at zero load
static float g_counts_per_gram = 1.0f; // how many counts per 1 gram

/* ---- Helpers ---- */
static esp_err_t nvs_save_cal(float counts_per_gram, int32_t offset) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK)
    return err;

  err = nvs_set_i32(nvs, NVS_KEY_OFFSET, offset);
  if (err == ESP_OK) {
    // store float as blob
    err = nvs_set_blob(nvs, NVS_KEY_SCALE, &counts_per_gram,
                       sizeof(counts_per_gram));
  }
  if (err == ESP_OK)
    err = nvs_commit(nvs);
  nvs_close(nvs);
  return err;
}

static esp_err_t nvs_load_cal(float *counts_per_gram, int32_t *offset) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK)
    return err;

  err = nvs_get_i32(nvs, NVS_KEY_OFFSET, offset);
  if (err != ESP_OK) {
    nvs_close(nvs);
    return err;
  }

  size_t sz = sizeof(float);
  err = nvs_get_blob(nvs, NVS_KEY_SCALE, counts_per_gram, &sz);
  nvs_close(nvs);
  return err;
}

static esp_err_t do_tare_and_store(hx711_t *dev) {
  int32_t avg = 0;
  ESP_LOGI(hx711TAG, "Taring... (no load) reading %d samples", TARE_SAMPLES);
  ESP_ERROR_CHECK(hx711_read_average(dev, TARE_SAMPLES, &avg));
  g_offset = avg;
  ESP_LOGI(hx711TAG, "Offset (tare) = %" PRId32, g_offset);
  return nvs_save_cal(g_counts_per_gram, g_offset);
}

static esp_err_t do_calibrate_and_store(hx711_t *dev, float known_weight_g) {
  int32_t avg = 0;
  ESP_LOGI(hx711TAG, "Calibrating with %.1f g... (%d samples)", known_weight_g,
           CAL_SAMPLES);
  ESP_ERROR_CHECK(hx711_read_average(dev, CAL_SAMPLES, &avg));

  int32_t net = avg - g_offset;
  if (fabsf(known_weight_g) < 1e-3f) {
    ESP_LOGE(hx711TAG, "Known weight is zero!");
    return ESP_FAIL;
  }

  float cpg = (float)net / known_weight_g; // counts per gram
  if (cpg < 0)
    cpg = -cpg; // normalize sign if wiring inverted
  g_counts_per_gram = cpg;

  ESP_LOGI(hx711TAG, "Calibration done: counts_per_gram = %.3f",
           g_counts_per_gram);
  return nvs_save_cal(g_counts_per_gram, g_offset);
}

static float read_weight_g(hx711_t *dev, size_t samples) {
  int32_t avg = 0;
  if (hx711_read_average(dev, samples, &avg) != ESP_OK)
    return NAN;
  int32_t net = avg - g_offset;
  return net / g_counts_per_gram;
}
void myhx711_init(void) {

  // Init NVS (needed for saving/loading calibration)
  ESP_ERROR_CHECK(nvs_flash_init());

  // Setup HX711 pins & gain
  hx711.dout = GPIO_NUM_21;
  hx711.pd_sck = GPIO_NUM_22;
  hx711.gain = HX711_GAIN_A_128;

  if (hx711_init(&hx711) != ESP_OK) {
    ESP_LOGE(hx711TAG, "HX711 init failed");
    vTaskDelete(NULL);
  }

  ESP_LOGI(hx711TAG, "HX711 ready. Loading calibration from NVS...");
  if (nvs_load_cal(&g_counts_per_gram, &g_offset) != ESP_OK ||
      g_counts_per_gram < 1e-6f) {
    ESP_LOGW(hx711TAG, "No valid calibration found.");
    ESP_LOGI(hx711TAG,
             "Step 1: Remove all weight. Tare will start in 3 seconds...");
    gpio_set_level(LED_INDICATOR, 1); // LED on for Step 1
    vTaskDelay(pdMS_TO_TICKS(3000));
    ESP_ERROR_CHECK(do_tare_and_store(&hx711));
    gpio_set_level(LED_INDICATOR, 0); // LED off after step

    ESP_LOGI(hx711TAG, "Step 2: Place %.1f g on the scale within 5 seconds...",
             REF_WEIGHT_G);
    gpio_set_level(LED_INDICATOR, 1); // LED on for Step 2
    vTaskDelay(pdMS_TO_TICKS(5000));
    ESP_ERROR_CHECK(do_calibrate_and_store(&hx711, REF_WEIGHT_G));
    gpio_set_level(LED_INDICATOR, 0); // LED off after step
  } else {
    ESP_LOGI(hx711TAG, "Loaded: offset=%" PRId32 ", counts_per_gram=%.3f",
             g_offset, g_counts_per_gram);
  }
}
/* ---- Task ---- */
void hx711_task(void) {
  // Main loop: print weight
  // Check if BOOT button is pressed (LOW)

  if (gpio_get_level(BOOT_BTN) == 0) {
    ESP_LOGI(hx711TAG, "BOOT button pressed. Recalibrating...");

    // Step 1: Tare
    gpio_set_level(LED_INDICATOR, 1); // turn on indicator
    vTaskDelay(pdMS_TO_TICKS(3000));  // debounce
    ESP_ERROR_CHECK(do_tare_and_store(&hx711));
    gpio_set_level(LED_INDICATOR, 0); // turn off indicator
    vTaskDelay(pdMS_TO_TICKS(1000));  // debounce

    // Step 2: Calibrate with REF_WEIGHT_G
    ESP_LOGI(hx711TAG, "Place %.1f g weight for calibration", REF_WEIGHT_G);
    gpio_set_level(LED_INDICATOR, 1);
    vTaskDelay(pdMS_TO_TICKS(5000)); // give user time to place weight
    ESP_ERROR_CHECK(do_calibrate_and_store(&hx711, REF_WEIGHT_G));
    gpio_set_level(LED_INDICATOR, 0); // turn off indicator

    ESP_LOGI(hx711TAG, "Recalibration done!");
    // wait until button released
  }

  // Normal weight reading
  float g = read_weight_g(&hx711, RUN_SAMPLES);
  if (!isnan(g)) {
    float kg = g / 1000.0f;
    ESP_LOGI(hx711TAG, "Weight: %.1f g  (%.3f kg)", g, kg);
    weight = kg;

  } else {
    ESP_LOGE(hx711TAG, "Read error");
  }
}

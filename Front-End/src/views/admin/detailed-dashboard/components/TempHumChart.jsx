import React, { useState } from "react";
import {
  MdArrowDropUp,
  MdOutlineCalendarToday,
  MdBarChart,
} from "react-icons/md";
import Card from "components/card";
import { lineChartOptionsTotalSpent } from "variables/charts";
import LineChart from "components/charts/LineChart";
import dayjs from "dayjs";
import { LocalizationProvider } from "@mui/x-date-pickers/LocalizationProvider";
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import { DateTimePicker } from "@mui/x-date-pickers/DateTimePicker";
import { MdChevronRight } from "react-icons/md";

import Alert from "@mui/material/Alert";

export default function TempHumChart({ allSensorData = [] }) {
  const [startDate, setStartDate] = useState(dayjs());
  const [endDate, setEndDate] = useState(dayjs());
  const [currentSelectedData, setCurrentSelectedData] = useState([]);
  const [isFetchButtonClicked, setIsFetchButtonClicked] = useState(false);
  const [isDataRangeCorrect, setIsDataRangeCorrect] = useState(true);

  const allReading =
    allSensorData
      ?.filter(
        (sensor) =>
          sensor.timestamp &&
          sensor.temperature !== undefined &&
          sensor.humidity !== undefined
      )
      ?.map((sensor) => ({
        time: new Date(sensor.timestamp),
        temp: sensor.temperature,
        hum: sensor.humidity,
      })) || [];
  console.log(allReading);
  const prepareChartData = (sensorData) => {
    return [
      {
        name: "Temperature (°C)",
        data: sensorData.map((item) => parseFloat(item.temp)),
        color: "#D22B2B", // Purple for temperature
      },
      {
        name: "Humidity (%)",
        data: sensorData.map((item) => parseFloat(item.hum)),
        color: "#6AD2FF", // Light blue for humidity
      },
    ];
  };
  // Prepare categories (time labels) for x-axis
  const prepareCategories = (sensorData) => {
    return sensorData.map(
      (item) => dayjs(item.time).format("HH:mm") // Format as "17:15"
      // Alternatively: dayjs(item.time).format('DD/MM HH:mm') for date+time
    );
  };
  // Update chart options with dynamic categories
  const lineChartOptions = {
  ...lineChartOptionsTotalSpent, // Spread the existing options
  chart: {
    ...lineChartOptionsTotalSpent.chart,
    toolbar: {
      show: true,
    },
    animations: {
      enabled: false, //Disables all animations
    },
  },
  xaxis: {
    ...lineChartOptionsTotalSpent.xaxis,
    categories: prepareCategories(
      currentSelectedData.length > 0
        ? currentSelectedData
        : allReading.slice(-24)
    ),
    labels: {
      ...lineChartOptionsTotalSpent.xaxis.labels,
      formatter: function (value) {
        return value; // Use the formatted time string directly
      },
    },
    type: "category", // Better for time series
  },
  tooltip: {
    ...lineChartOptionsTotalSpent.tooltip,
    x: {
      format: "dd/MM/yy HH:mm", // Keep detailed format in tooltip
    },
  },
  yaxis: [
    {
      title: {
        text: "Temperature (°C)",
        style: {
          color: "#D22B2B",
        },
      },
      labels: {
        style: {
          colors: "#D22B2B",
        },
        formatter: function (value) {
          return value.toFixed(1); // Format temperature to 1 decimal place
        },
      },
      min: 0,
      max: 100,
      tickAmount: 10,
    },
    {
      opposite: true, // Place on the right side
      title: {
        text: "Humidity (%)",
        style: {
          color: "#6AD2FF",
        },
      },
      labels: {
        style: {
          colors: "#6AD2FF",
        },
        formatter: function (value) {
          return value.toFixed(1); // Format humidity to 1 decimal place
        },
      },
      min: 0,
      max: 100,
      tickAmount: 10,
    },
  ],
};

  ///Fetch button handler ///
  function fetchChartHandler() {
    // Convert Day.js objects to JavaScript Date objects
    const start = new Date(startDate.startOf("day").toDate());
    const end = new Date(endDate.endOf("day").toDate());

    // Filter data within the selected date range
    const filteredData = allReading.filter((reading) => {
      const readingTime = reading.time;
      return readingTime >= start && readingTime <= end;
    });

    setCurrentSelectedData(filteredData);
    setIsFetchButtonClicked(true);
    console.log("Filtered data:", filteredData); // For debugging
    if (filteredData.length === 0) {
      setIsDataRangeCorrect(false);
    } else {
      setIsDataRangeCorrect(true);
    }
  }

  return (
    <Card extra="!p-[20px] text-center">
      {!isDataRangeCorrect ? (
        <div className="mb-2">
          <Alert severity="warning">
            Invalid date range: End date must be after Start date!
          </Alert>
        </div>
      ) : null}

      <LocalizationProvider dateAdapter={AdapterDayjs}>
        <div className="flex w-full items-center gap-4">
          {/* Start Date - Takes available space */}
          <div className="min-w-[150px] flex-1">
            <DateTimePicker
              label="Start Date"
              format="MM/DD/YYYY"
              value={startDate}
              onChange={(newValue) => setStartDate(newValue)}
              slotProps={{
                textField: {
                  size: "small",
                  fullWidth: true,
                },
              }}
            />
          </div>

          {/* End Date - Takes available space */}
          <div className="min-w-[150px] flex-1">
            <DateTimePicker
              label="End Date"
              format="MM/DD/YYYY"
              value={endDate}
              onChange={(newValue) => setEndDate(newValue)}
              slotProps={{
                textField: {
                  size: "small",
                  fullWidth: true,
                },
              }}
            />
          </div>

          {/* Button - Fixed width */}
          <button
            className="flex shrink-0 items-center whitespace-nowrap rounded-xl bg-brand-500 px-4 py-3 text-base font-medium text-white hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300"
            onClick={fetchChartHandler}
          >
            Fetch chart <MdChevronRight className="ml-1 text-lg" />
          </button>
        </div>
      </LocalizationProvider>

      <div className="flex h-full w-full flex-row justify-between sm:flex-wrap lg:flex-nowrap 2xl:overflow-hidden">
        <div className="h-[400px] w-full">
          <LineChart
            options={lineChartOptions}
            series={prepareChartData(
              currentSelectedData.length > 0
                ? currentSelectedData
                : allReading.slice(-24)
            )}
          />
        </div>
        {/*
         */}
      </div>
    </Card>
  );
}

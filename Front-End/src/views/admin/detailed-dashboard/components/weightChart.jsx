import React, { useState } from "react";
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
  const [isDataRangeCorrect, setIsDataRangeCorrect] = useState(true);

  // process only weight
  const allReading =
    allSensorData
      ?.filter(
        (sensor) =>
          sensor.timestamp &&
          sensor.weight !== undefined
      )
      ?.map((sensor) => ({
        time: new Date(sensor.timestamp),
        weight: sensor.weight,
      })) || [];

  const prepareChartData = (sensorData) => {
    return [
      {
        name: "Weight (kg)",
        data: sensorData.map((item) => parseFloat(item.weight)),
        color: "#2E8B57", // forest green
      },
    ];
  };

  const prepareCategories = (sensorData) => {
    return sensorData.map((item) =>
      dayjs(item.time).format("HH:mm")
    );
  };

  const lineChartOptions = {
    ...lineChartOptionsTotalSpent,
    chart: {
      ...lineChartOptionsTotalSpent.chart,
      toolbar: {
        show: true,
      },
      animations: {
        enabled: false,
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
          return value;
        },
      },
      type: "category",
    },
    tooltip: {
      ...lineChartOptionsTotalSpent.tooltip,
      x: {
        format: "dd/MM/yy HH:mm",
      },
    },
    yaxis: [
      {
        title: {
          text: "Weight (kg)",
          style: {
            color: "#2E8B57",
          },
        },
        labels: {
          style: {
            colors: "#2E8B57",
          },
          formatter: function (value) {
            return value.toFixed(1);
          },
        },
        min: 0,
        max: 100, // adjust this to match your expected weight range
        tickAmount: 10,
      },
    ],
  };

  function fetchChartHandler() {
    const start = new Date(startDate.startOf("day").toDate());
    const end = new Date(endDate.endOf("day").toDate());

    const filteredData = allReading.filter((reading) => {
      const readingTime = reading.time;
      return readingTime >= start && readingTime <= end;
    });

    setCurrentSelectedData(filteredData);

    if (filteredData.length === 0) {
      setIsDataRangeCorrect(false);
    } else {
      setIsDataRangeCorrect(true);
    }
  }

  return (
    <Card extra="!p-[20px] text-center">
      {!isDataRangeCorrect && (
        <div className="mb-2">
          <Alert severity="warning">
            Invalid date range: End date must be after Start date!
          </Alert>
        </div>
      )}

      <LocalizationProvider dateAdapter={AdapterDayjs}>
        <div className="flex w-full items-center gap-4">
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
      </div>
    </Card>
  );
}

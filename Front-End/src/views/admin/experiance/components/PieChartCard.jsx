import React, { useState, useEffect } from "react";
import PieChart from "components/charts/PieChart";
import { pieChartData, pieChartOptions } from "variables/charts";
import Card from "components/card";

const PieChartCard = () => {
    const [healthStatusCounts, setHealthStatusCounts] = useState([]);
    const [healthy, setHealthy] = useState(0);
    const [unhealthy, setUnhealthy] = useState(0);
    const [noData, setNoData] = useState(0);
    
const pieChartData = [healthy, unhealthy, noData];

const pieChartOptions = {
  labels: ["Healthy", "Unhealthy", "No Data"],
  colors: ["#008000", "#FFA500", "#808080"],
  chart: {
    width: "50px",
  },
  states: {
    hover: {
      filter: {
        type: "none",
      },
    },
  },
  legend: {
    show: false,
  },
  dataLabels: {
    enabled: false,
  },
  hover: { mode: null },
  plotOptions: {
    donut: {
      expandOnClick: false,
      donut: {
        labels: {
          show: false,
        },
      },
    },
  },
  fill: {
    colors: ["#5CE65C", "#FF5F15", "#808080"],
  },
  tooltip: {
    enabled: true,
    theme: "dark",
    style: {
      fontSize: "12px",
      fontFamily: undefined,
      backgroundColor: "#000000"
    },
  },
};


useEffect(() => {
  const fetchHealthStatusCount = async () => {
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/health-status-count`, {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("Failed to fetch health status counts");
      }
      const data = await response.json();
      setHealthStatusCounts(data);
      console.log("Health Status Counts:", data);

      // Parse counts for each status
      const healthyCount = data.find(item => item.health_status.toLowerCase() === 'healthy')?.count || 0;
      const unhealthyCount = data.find(item => item.health_status.toLowerCase() === 'unhealthy')?.count || 0;
      const noDataCount = data.find(item => item.health_status.toLowerCase() === 'no data')?.count || 0;

      setHealthy(Number(healthyCount));
      setUnhealthy(Number(unhealthyCount));
      setNoData(Number(noDataCount));

    } catch (error) {
      console.error("Error fetching health status counts:", error);
      setHealthy(0);
      setUnhealthy(0);
      setNoData(0);
    }
  };

  fetchHealthStatusCount();
}, []); 

const total = healthy + unhealthy + noData;

const healthyPercent = total ? ((healthy / total) * 100).toFixed(0) : 0;
const unhealthyPercent = total ? ((unhealthy / total) * 100).toFixed(0) : 0;
const noDataPercent = total ? ((noData / total) * 100).toFixed(0) : 0;

 return (
    <Card extra="rounded-[20px] p-3">
      <div className="flex flex-row justify-between px-3 pt-2">
        <div>
          <h4 className="text-lg font-bold text-navy-700 dark:text-white">
            Your Beehives Overview
          </h4>
           <div className="ml-1 pt-2">
          <p className="text-sm font-medium leading-4 text-gray-600">
            Totale
          </p>
          <p className="text-[34px] font-bold text-navy-700 dark:text-white">
            {total}{" "}
            <span className="text-sm font-medium leading-6 text-gray-600">
              hives
            </span>
          </p>
        </div>
        </div>

        <div className="mb-6 flex items-center justify-center">
          <select className="mb-3 mr-2 flex items-center justify-center text-sm font-bold text-gray-600 hover:cursor-pointer dark:!bg-navy-800 dark:text-white">
            <option value="monthly">Monthly</option>
            <option value="yearly">Yearly</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>
      </div>

      <div className="mb-auto flex h-[220px] w-full items-center justify-center">
        <PieChart options={pieChartOptions} series={pieChartData} />
      </div>
      <div className="flex flex-row !justify-between rounded-2xl px-6 py-3 shadow-2xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
        <div className="flex flex-col items-center justify-center">
          <div className="flex items-center justify-center">
            <div className="h-2 w-2 rounded-full bg-[#008000]" />
            <p className="ml-1 text-sm font-normal text-gray-600">Healthy</p>
          </div>
          <p className="mt-px text-xl font-bold text-navy-700  dark:text-white">
    {healthyPercent}%
          </p>
        </div>

        <div className="h-11 w-px bg-gray-300 dark:bg-white/10" />

        <div className="flex flex-col items-center justify-center">
          <div className="flex items-center justify-center">
            <div className="h-2 w-2 rounded-full bg-[#ff5733]" />
            <p className="ml-1 text-sm font-normal text-gray-600">Unhealthy</p>
          </div>
          <p className="mt-px text-xl font-bold text-navy-700 dark:text-white">
    {unhealthyPercent}%
          </p>
        </div>
      </div>
    </Card>
  );
};

export default PieChartCard;
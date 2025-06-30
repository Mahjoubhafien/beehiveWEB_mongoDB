import { useEffect, useState } from "react";
import BarChart from "components/charts/BarChart";
import { MdArrowDropUp } from "react-icons/md";
import Card from "components/card";
const DailyTraffic = () => {
      const [healthStatusCounts, setHealthStatusCounts] = useState([]);
      const [healthy, setHealthy] = useState(0);
      const [unhealthy, setUnhealthy] = useState(0);
      const [noData, setNoData] = useState(0);
      const barChartDataDailyTraffic = [
  {
    name: "Daily Traffic",
    data: [20, 30, 40, 20, 45, 50, 30],
  },
];

const barChartOptionsDailyTraffic = {
  chart: {
    toolbar: {
      show: false,
    },
  },
  tooltip: {
    style: {
      fontSize: "12px",
      fontFamily: undefined,
      backgroundColor: "#000000"
    },
    onDatasetHover: {
      style: {
        fontSize: "12px",
        fontFamily: undefined,
      },
    },
    theme: "dark",
  },
  xaxis: {
    categories: ["00", "04", "08", "12", "14", "16", "18"],
    show: false,
    labels: {
      show: true,
      style: {
        colors: "#A3AED0",
        fontSize: "14px",
        fontWeight: "500",
      },
    },
    axisBorder: {
      show: false,
    },
    axisTicks: {
      show: false,
    },
  },
  yaxis: {
    show: false,
    color: "black",
    labels: {
      show: true,
      style: {
        colors: "#CBD5E0",
        fontSize: "14px",
      },
    },
  },
  grid: {
    show: false,
    strokeDashArray: 5,
    yaxis: {
      lines: {
        show: true,
      },
    },
    xaxis: {
      lines: {
        show: false,
      },
    },
  },
  fill: {
    type: "gradient",
    gradient: {
      type: "vertical",
      shadeIntensity: 1,
      opacityFrom: 0.7,
      opacityTo: 0.9,
      colorStops: [
        [
          {
            offset: 0,
            color: "#4318FF",
            opacity: 1,
          },
          {
            offset: 100,
            color: "rgba(67, 24, 255, 1)",
            opacity: 0.28,
          },
        ],
      ],
    },
  },
  dataLabels: {
    enabled: false,
  },
  plotOptions: {
    bar: {
      borderRadius: 10,
      columnWidth: "40px",
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
  return (
    <Card extra="pb-7 p-[20px]">
      <div className="flex flex-row justify-between">
        <div className="ml-1 pt-2">
          <p className="text-sm font-medium leading-4 text-gray-600">
            Healthy Hives
          </p>
          <p className="text-[34px] font-bold text-navy-700 dark:text-white">
            {healthy}{" "}
            <span className="text-sm font-medium leading-6 text-gray-600">
              Hives
            </span>
          </p>
        </div>
        <div className="mt-2 flex items-start">
          <div className="flex items-center text-sm text-green-500">
            <MdArrowDropUp className="h-5 w-5" />
            <p className="font-bold"> +2.45% </p>
          </div>
        </div>
      </div>

      <div className="h-[300px] w-full pt-10 pb-0">
        <BarChart
          chartData={barChartDataDailyTraffic}
          chartOptions={barChartOptionsDailyTraffic}
        />
      </div>
    </Card>
  );
};

export default DailyTraffic;
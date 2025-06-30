import { useEffect, useState } from "react";
import DailyTraffic from "views/admin/experiance/components/DailyTraffic";
import PieChartCard from "views/admin/experiance/components/PieChartCard";

const Experiance = () => {
    const [alerts, setAlerts] = useState([]);
useEffect(() => {
    const fetchAlerts = async () => {
      try {
const response = await fetch(`${process.env.REACT_APP_API_URL}/api/alerts-history`, {
  credentials: "include"
});
        if (!response.ok) {
          throw new Error("Failed to fetch alerts history");
        }
        const data = await response.json();
        setAlerts(data);
        console.log(data);
      } catch (error) {
        console.error("Error fetching alerts history:", error);
      }
    };

    fetchAlerts();
  }, []);

  const columnsData = [
  { Header: "ID", accessor: "id" },
  { Header: "Alert Type", accessor: "alert_type" },
  { Header: "Status", accessor: "status" },
  { Header: "Sensor ID", accessor: "sensor_id" },
  { Header: "Date", accessor: "date" },
];
  return (
    <div>


      <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-1">
       
        {/* Traffic chart & Pie Chart */}

        <div className="grid grid-cols-1 gap-5 rounded-[20px] md:grid-cols-2">
          <DailyTraffic />
          <PieChartCard />
        </div>

        {/* Task chart & Calendar */}

        {/*<div className="grid grid-cols-1 gap-5 rounded-[20px] md:grid-cols-2">
          <TaskCard />
          <div className="grid grid-cols-1 rounded-[20px]">
            <MiniCalendar />
          </div>
        </div>*/}
      </div>
    </div>
  );
};


export default Experiance;
import { useEffect, useState } from "react";
import AlertsHistory from "views/admin/alerts/components/ComplexTable";

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
        {/* Complex Table , Task & Calendar */}

        <AlertsHistory
          columnsData={columnsData}
          tableData={alerts}
        />

        
      </div>
    </div>
  );
};


export default Experiance;
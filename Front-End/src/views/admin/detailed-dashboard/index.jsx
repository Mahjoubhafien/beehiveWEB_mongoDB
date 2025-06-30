import React, { useEffect, useState } from "react";
import MiniCalendar from "components/calendar/MiniCalendar";
import PieChartCard from "views/admin/detailed-dashboard/components/PieChartCard";
import Chart from "./components/TempHumChart";
import WeightChart from "./components/weightChart";
import { FaTemperatureQuarter } from "react-icons/fa6";
import { WiHumidity } from "react-icons/wi";
import { GiWeight } from "react-icons/gi";
import { IoLocation } from "react-icons/io5";
import GppGoodIcon from "@mui/icons-material/GppGood";
import GppBadIcon from "@mui/icons-material/GppBad";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import { MdSensors } from "react-icons/md";
import Alert from "@mui/material/Alert";
import CloseIcon from "@mui/icons-material/Close";
import IconButton from "@mui/material/IconButton";
import MapComponent from "./components/GpsMap";
import CircularProgress from "@mui/material/CircularProgress";
import Box from "@mui/material/Box";
import MultipleSelectChip from "./components/Selecthive";
import Widget from "components/widget/Widget";
import { MdDelete } from "react-icons/md";
import { useNavigate } from 'react-router-dom'; 
import WeeklyRevenue from "views/admin/detailed-dashboard/components/WeeklyRevenue";

const Dashboard = () => {
  const [allSensorData, setAllSensorData] = useState([]);
  const [sensorLoation, setSensorLoation] = useState();
  const [latestSensor, setLatestSensor] = useState(); // n data
  const [isWarningOn, setIsWarningOn] = useState(false);
  const [isCloseButtonPressed, setIsCloseButtonPressed] = useState(false);
  const [allSensors, setAllSensors] = useState([]);
  const [currentSensorId, setCurrentSensorId] = useState("Select Sensor");
  const [IsNoDataWarning, setIsNoDataWarning] = useState(false);
  const [hiveHealth, sethiveHealth] = useState("Checking");


    const MIN_TEMP = 32;
    const MAX_TEMP = 36;
    const MIN_HUMIDITY = 50;
    const MAX_HUMIDITY = 70;

async function updateSensorDataFromSelect() {
  try {
    const response = await fetch(
      `${process.env.REACT_APP_API_URL}/admin/getCurrentSensorData`, {
        credentials: "include",
        headers: {
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
        },
      }
    );

    if (response.status === 401) {
      navigate('/auth/sign-in'); // Redirect if unauthorized
      return;
    }
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const sensorData = await response.json();
    const latest = sensorData[sensorData.length - 1];

    if (!latest || latest.temperature == null || latest.humidity == null) {
      setIsNoDataWarning(true);
      sethiveHealth("No Data");
      return;
    }

    setAllSensorData(sensorData);

    if (
      latest.temperature >= MIN_TEMP &&
      latest.temperature <= MAX_TEMP &&
      latest.humidity >= MIN_HUMIDITY &&
      latest.humidity <= MAX_HUMIDITY
    ) {
      sethiveHealth("Healthy");
      setIsWarningOn(false);
      setIsNoDataWarning(false);
    } else {
      sethiveHealth("Unhealthy");
      setIsWarningOn(true);
      setIsNoDataWarning(false);
    }

    if (sensorData.length > 0) {
      setLatestSensor(latest);
    }
  } catch (err) {
    console.error("Error fetching data:", err);
  }
}
  
  /////////// Fetch the selected Sensor data, repeated every 1s ( you can change it) ////////
  const navigate = useNavigate();
  useEffect(() => {
    const fetchCurrentSensorData = async () => {
      const MIN_TEMP = 32;
    const MAX_TEMP = 36;
    const MIN_HUMIDITY = 50;
    const MAX_HUMIDITY = 70;

    try {
      const response = await fetch(
        `${process.env.REACT_APP_API_URL}/admin/getCurrentSensorData`,{
          credentials: "include",
          headers: {
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
          },
        });
        if (response.status === 401) {
        navigate('/auth/sign-in'); // Redirect if unauthorized
        return;
      }
       if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const sensorData = await response.json();
      const latest = sensorData[sensorData.length - 1];
      //console.log(latest);
      //return health no data when temp and hum null
      if (!latest || latest.temperature == null || latest.humidity == null) {
        setIsNoDataWarning(true);
        sethiveHealth("No Data");
        return;
      }
      setAllSensorData(sensorData);
      if (
        sensorData[sensorData.length - 1].temperature >= MIN_TEMP &&
        sensorData[sensorData.length - 1].temperature <= MAX_TEMP &&
        sensorData[sensorData.length - 1].humidity >= MIN_HUMIDITY &&
        sensorData[sensorData.length - 1].humidity <= MAX_HUMIDITY
      ) {
        sethiveHealth("Healthy");
        setIsWarningOn(false);
        setIsNoDataWarning(false);
      } else {
        sethiveHealth("Unhealthy");
        setIsWarningOn(true);
        setIsNoDataWarning(false);
      }
      // Set the latest sensor value after data is fetched
      if (sensorData.length > 0) {
        setLatestSensor(sensorData[sensorData.length - 1]);
      }
    } catch (err) {
      console.error("Error fetching data:", err);
    }
  };
    fetchCurrentSensorData();

    // Set interval to fetch every 10second
    const interval = setInterval(fetchCurrentSensorData,10000);

    // Clear interval on unmount
    return () => clearInterval(interval);
  }, [navigate]);
  ////////// fetch the current location ///////////
  useEffect(() => {
    const fetchSensorLocation = async () => {
        if (latestSensor && latestSensor.latitude && latestSensor.longitude) {
            try {
  const response = await fetch(
    `${process.env.REACT_APP_API_URL}/admin/getHiveLocation?latitude=${latestSensor.latitude}&longitude=${latestSensor.longitude}`
  );
                const location = await response.json();
                setSensorLoation(location.city);
            } catch (err) {
                console.error("Error fetching location:", err);
            }
        }
    };

    fetchSensorLocation();
}, [latestSensor]);  // This will run whenever latestSensor changes

  //////// fetch all sensor id that i have, to select them in the detailed dashboard page /////////
  useEffect(() => {
    const fetchSensorIds = async () => {
      try {
        const response = await fetch(`${process.env.REACT_APP_API_URL}/admin/sensor-ids`,{
          credentials: "include",
          headers: {
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
          },
        });
         if (response.status === 401) {
        navigate('/auth/sign-in'); // Redirect if unauthorized
        return;
      }
       if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
        const data = await response.json();
        const sensorIds = data.map((item) => item.sensor_id);
        setAllSensors(sensorIds);
      } catch (error) {
        console.error("Error fetching sensor IDs:", error);
      }
    };

    fetchSensorIds();
  }, []);

  useEffect(() => {
    const fetchCurrentSensorId = async () => {
try {
  const response = await fetch(
    `${process.env.REACT_APP_API_URL}/admin/current-sensor`,{
          credentials: "include",
          headers: {
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
          },
        });
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        const data = await response.json();
        setCurrentSensorId(data.currentSensorId);
      } catch (error) {
        console.error("Error fetching sensor IDs:", error);
      }
    };

    fetchCurrentSensorId();
  }, []);
  
const handleDeleteHive = async () => {
  const confirmed = window.confirm(
    "Are you sure you want to delete this hive? You will lose all hive data."
  );

  if (!confirmed) {
    console.log("User canceled deletion");
    return;
  }

  try {
    console.log("User confirmed deletion");

    const response = await fetch(
      `${process.env.REACT_APP_API_URL}/api/delete-hive`,
      {
        method: "DELETE",
        credentials: "include", // Required for session/cookie-based auth
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Failed to delete hive");
    }

    alert("Hive deleted successfully!");

    window.location.href = "/admin/all-hives";
  } catch (error) {
    console.error("Error deleting hive:", error);
    alert(error.message || "An error occurred while deleting the hive.");
  }
};


/**/ 
  return (
    <div>
      {latestSensor ? (
        IsNoDataWarning ? (
          <Alert variant="filled" severity="info" className="mt-5">
            No data received for the sensor, Please check device power or
            network connection.
          </Alert>
        ) : isWarningOn ? (
          <Alert variant="filled" severity="warning" className="mt-5">
            Alert: Signs of hive distress detected, check for queen loss or
            disease!
          </Alert>
        ) : (
          !isCloseButtonPressed && (
            <Alert variant="filled" severity="success" className="mt-5">
              Hive status normal, all conditions within optimal range.{" "}
              <IconButton
                aria-label="close"
                color="inherit"
                size="small"
                onClick={() => {
                  // Add your close handler logic here
                  setIsCloseButtonPressed(true);
                }}
              >
                <CloseIcon fontSize="inherit" />
              </IconButton>
            </Alert>
          )
        )
      ) : null}
  <div className="flex items-center justify-between mt-1">
    <MultipleSelectChip
      allSonsorsIds={allSensors}
      currentSensorId={currentSensorId}
      updateSensorDataFromSelect={updateSensorDataFromSelect}
    />
    
    <button
      className="flex items-center gap-1 rounded-xl bg-red-500 px-5 py-3 text-base font-medium text-white transition duration-200 hover:bg-red-600 active:bg-red-700 dark:bg-red-400 dark:text-white dark:hover:bg-red-300 dark:active:bg-red-200"
      onClick={handleDeleteHive}
    >
      Delete Hive <MdDelete />

    </button>
  </div>
      {/* Card widget */}
      <div className="mt-3 grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-3 3xl:grid-cols-6">
        <Widget
          icon={<FaTemperatureQuarter className="h-7 w-7" />}
          title={"Temperature"}
          subtitle={
            latestSensor ? `${latestSensor.temperature} °C` : "Loading..."
          }
        />
        <Widget
          icon={<WiHumidity className="h-6 w-6" />}
          title={"Humidity"}
          subtitle={latestSensor ? `${latestSensor.humidity} %` : "Loading..."}
        />
        <Widget
          icon={<GiWeight className="h-7 w-7" />}
          title={"Weight"}
subtitle={
    latestSensor?.weight != null
      ? `${latestSensor.weight} Kg`
      : "Loading..."
  }
        />
        <Widget
          icon={<IoLocation className="h-6 w-6" />}
          title={"Location"}
          subtitle={sensorLoation ? sensorLoation : "Loading..."}
        />
        <Widget
          bg_color={
            latestSensor
              ? isWarningOn
                ? "!bg-red-100" // Warning state (red background)
                : IsNoDataWarning
                ? null // No data state (gray background)
                : "!bg-green-100" // Normal state (green background)
              : null // Fallback when no latestSensor (gray background)
          }
          icon={<GppGoodIcon className="h-7 w-7" />}
          title={"State"}
          subtitle={latestSensor ? hiveHealth : "Loading..."}
        />
        <Widget
          icon={<MdSensors className="h-6 w-6" />}
          title={"sensor Id"}
          subtitle={latestSensor ? latestSensor.sensor_id : "Loading..."}
        />
      </div>

      {/* Charts */}

      {/*<div className="mt-5 grid grid-cols-1 gap-5 md:grid-cols-2">
        <Chart />
        <WeeklyRevenue />
      </div>*/}

      <div className="mt-5 grid grid-cols-1 gap-5 md:grid-cols-2">
        <Chart allSensorData={allSensorData} />
        <WeightChart allSensorData={allSensorData} />

      </div>
      <div className="mt-5 grid grid-cols-1 gap-5 md:grid-cols-1">
{latestSensor && latestSensor.latitude != null && latestSensor.longitude != null ? (
  <MapComponent lat={latestSensor.latitude} lng={latestSensor.longitude} />
) : (       
     <div>
            <Box
              sx={{
                display: "flex",
                justifyContent: "center", // horizontal centering
                alignItems: "center", // vertical centering
                height: "100%", // takes full height of parent
              }}
            >
              <CircularProgress />
            </Box>
          </div>
        )}
      </div>

      {/* Tables & Charts - Entire Section Commented Out
<div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-2">
  {/* Check Table * /}
  <div>
    <CheckTable
      columnsData={columnsDataCheck}
      tableData={tableDataCheck}
    />
  </div>

  {/* Traffic chart & Pie Chart * /}

  <div className="grid grid-cols-1 gap-5 rounded-[20px] md:grid-cols-2">
    <DailyTraffic />
    <PieChartCard />
  </div>

  {/* Complex Table, Task & Calendar * /}

  <ComplexTable
    columnsData={columnsDataComplex}
    tableData={tableDataComplex}
  />

  {/* Task chart & Calendar * /}

  <div className="grid grid-cols-1 gap-5 rounded-[20px] md:grid-cols-2">
    <TaskCard />
    <div className="grid grid-cols-1 rounded-[20px]">
      <MiniCalendar />
    </div>
  </div>
</div>
*/}
    </div>
  );
};

export default Dashboard;

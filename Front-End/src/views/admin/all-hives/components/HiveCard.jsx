import { IoHeart, IoHeartOutline } from "react-icons/io5";
import { useState, useEffect } from "react";
import Card from "components/card";
import DeviceThermostatIcon from "@mui/icons-material/DeviceThermostat";
import WaterDropIcon from "@mui/icons-material/WaterDrop";
import GppGoodIcon from "@mui/icons-material/GppGood";
import GppBadIcon from "@mui/icons-material/GppBad";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import MapIcon from "@mui/icons-material/Map";
import { MdGpsFixed } from "react-icons/md";
import SensorsIcon from "@mui/icons-material/Sensors";
import SensorsOffIcon from "@mui/icons-material/SensorsOff";
import Tooltip from "@mui/material/Tooltip";
import { FaEdit } from "react-icons/fa";
import BasicTextFields from "./TextField.jsx";
import { background } from "@chakra-ui/system";

const HiveCard = ({
  hiveName,
  id,
  Temperature,
  Humidity,
  Location,
  Longitude,
  Latitude,
  image,
  link,
  lastDataR,
  onHealthStatusChange,
  GpsErrorHandler,
  editWarnnigHandler,
  updateHivesCard,
  extra,
}) => {
  const [IsEditButtenPresed, setIsEditButtenPresed] = useState(false);
  const [healthStatus, setHealthStatus] = useState("Checking...");
  const [sensorLocation, setSensorLocation] = useState("");
  const [isRed, setIsRed] = useState(false);

  const [newHiveName, setNewHiveName] = useState("");
  const [newSensorid, setNewSensorid] = useState("");
  const [newHiveLocation, setNewHiveLocation] = useState("");
  const [isGpsCorrect, setIsGpsCorrect] = useState(true);

  useEffect(() => {
    const interval = setInterval(() => {
      setIsRed((prev) => !prev);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

useEffect(() => {
  const checkHiveHealth = async (Temperature, Humidity) => {
    const MIN_TEMP = 32;
    const MAX_TEMP = 36;
    const MIN_HUMIDITY = 50;
    const MAX_HUMIDITY = 70;

    if (Temperature === null || Humidity === null) {
      return "No Data";
    }

    if (
      Temperature >= MIN_TEMP &&
      Temperature <= MAX_TEMP &&
      Humidity >= MIN_HUMIDITY &&
      Humidity <= MAX_HUMIDITY
    ) {
      return "Healthy";
    }

    // Determine specific issues
    let alertType = "hive_health";
    let statusMessage = "Unhealthy - ";
    let issues = [];

    if (Temperature < MIN_TEMP) {
      issues.push(`Low Temperature (${Temperature}°C)`);
      alertType = "temperature_alert";
    } else if (Temperature > MAX_TEMP) {
      issues.push(`High Temperature (${Temperature}°C)`);
      alertType = "temperature_alert";
    }

    if (Humidity < MIN_HUMIDITY) {
      issues.push(`Low Humidity (${Humidity}%)`);
      alertType = issues.length > 1 ? "combined_alert" : "humidity_alert";
    } else if (Humidity > MAX_HUMIDITY) {
      issues.push(`High Humidity (${Humidity}%)`);
      alertType = issues.length > 1 ? "combined_alert" : "humidity_alert";
    }

    statusMessage += issues.join(" and ");

    // Log alert to database
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/alerts-history`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          alert_type: alertType,
          status: statusMessage,
          sensor_id: id // Replace with actual sensor ID
        })
      });

      if (!response.ok) {
        throw new Error('Failed to log alert');
      }
    } catch (error) {
      console.error('Error logging alert:', error);
    }

    return "Unhealthy";
  };

  // Call the function and update state
  const updateHealthStatus = async () => {
    const status = await checkHiveHealth(Temperature, Humidity);
    onHealthStatusChange(status); // Make sure this is called
    setHealthStatus(status); // Update local state if needed

    try {
      await fetch(`${process.env.REACT_APP_API_URL}/admin/insertState`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          healthStatus: status,
          id,
        }),
      });
    } catch (err) {
      console.error("Error sending health status:", err);
    }
  
  };
  updateHealthStatus();
}, [Temperature, Humidity]);


{/*useEffect(() => {
    const sendHiveState = async () => {
      try {
        await fetch(`${process.env.REACT_APP_API_URL}/admin/insertState`, {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            healthStatus,
            id,
          }),
        });
      } catch (err) {
        console.error("Error fetching data:", err);
      }
    };
    sendHiveState();
  }, [healthStatus, id]);*/}

  ////////// check if the gps i putted correct ////////
  useEffect(() => {
    const fetchLocation = async () => {
      try {
        //console.log(Latitude,Longitude)
        const response = await fetch(
          `${process.env.REACT_APP_API_URL}/admin/getHiveLocation?latitude=${Latitude}&longitude=${Longitude}`
        );
        const locationData = await response.json();
        setSensorLocation(locationData.city); // e.g., "Tunis"

        // Normalize strings for comparison
        const normalizeString = (str) => {
          if (!str) return "";
          return str
            .toLowerCase() // Case-insensitive
            .trim() // Remove whitespace
            .normalize("NFD") // Convert accents to base characters (é → e)
            .replace(/[\u0300-\u036f]/g, "") // Remove diacritics
            .replace(/[أ-ي]/g, (char) => {
              // Optional: Map Arabic to Latin equivalents
              const arabicToLatin = {
                ت: "t",
                و: "o",
                ن: "n",
                س: "s", // Example: "تونس" → "tunis"
                // Add more mappings as needed
              };
              return arabicToLatin[char] || char;
            });
        };

        // Normalize both the GPS city and user input
        const normalizedGpsCity = normalizeString(locationData.city); // "tunis"
        const normalizedUserInput = normalizeString(Location); // e.g., "تونس" → "tunis"

        // Check if they match (flexibly)
        const isCorrect =
          Latitude !== null &&
          Longitude !== null &&
          (normalizedGpsCity === normalizedUserInput ||
            normalizedGpsCity.includes(normalizedUserInput) ||
            normalizedUserInput.includes(normalizedGpsCity));
        setIsGpsCorrect(isCorrect);
        //console.log(isCorrect);
        GpsErrorHandler(id, hiveName, isCorrect);
      } catch (error) {
        console.error("Error fetching location:", error);
      }
    };

    if (Latitude && Longitude) fetchLocation();
  }, [Latitude, Longitude, Location]);

  //edit hive function
  const editHiveHandler = async () => {
    setIsEditButtenPresed(!IsEditButtenPresed);
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/admin/edit-hive`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          newHiveName,
          newSensorid,
          newHiveLocation,
          id,
        }),
      });
      const result = await response.json();

      if (!response.ok) {
        console.error("Server Error:", result.message);
        editWarnnigHandler(result.message);
        return;
      }
      setNewHiveLocation("");
      setNewSensorid("");
      setNewHiveName("");
      updateHivesCard();
    } catch (err) {
      console.error("Error Updating  Hive:", err);
    }
  };

  return (
    <Card
      extra={`flex flex-col w-full h-full !p-4 3xl:p-![18px] bg-white ${extra}`}
    >
      <div className="h-full w-full">
        <div className="relative w-full">
          <div className="relative mb-1 h-36 w-full overflow-hidden rounded-xl">
            {/*    Image Field */}
            <button
              onClick={async () => {
                await fetch(
                  `${process.env.REACT_APP_API_URL}/admin/detailed-dashboard/${id}`,{
          credentials: "include",
          headers: {
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
          },
        });
                window.location.href = link;
              }}
              className="group overflow-hidden" // Added overflow-hidden to contain the scaled image
            >
              <img
                src={image}
                className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-110"
                alt={`Hive ${hiveName}`}
              />
            </button>
            {/*    Edit Button  */}
            <button
              onClick={() => setIsEditButtenPresed(!IsEditButtenPresed)}
              className="absolute right-1 top-1 flex items-center justify-center rounded-full bg-white bg-opacity-80 p-2 text-brand-500 transition-all duration-200 hover:cursor-pointer hover:bg-opacity-100"
            >
              <div className="flex h-full w-full items-center justify-center rounded-full text-xl hover:bg-gray-50 dark:text-navy-900">
                {IsEditButtenPresed ? (
                  <FaEdit />
                ) : (
                  <FaEdit className="text-brand-500" />
                )}
              </div>
            </button>
            {/**/}
          </div>
        </div>

        <div className="mb-3 flex items-center justify-between px-1 md:flex-col md:items-start lg:flex-row lg:justify-between xl:flex-col xl:items-start 3xl:flex-row 3xl:justify-between">
          <div className="mb-1">
            {/*    Name Field + the editin fiels text */}
            <div className="flex w-full items-center gap-2 text-lg font-bold text-navy-700 dark:text-white">
              <div
                className={`flex-grow ${IsEditButtenPresed ? "max-w-xs" : ""}`}
              >
                {IsEditButtenPresed ? (
                  <div>
                    <BasicTextFields
                      className="w-full rounded-md px-2 py-1"
                      label="New Hive Name"
                      value={newHiveName}
                      onChange={(e) => {
                        const { value } = e.target;
                        setNewHiveName(value);
                      }}
                    />

                    <BasicTextFields
                      className="w-full rounded-md px-2 py-1"
                      label="New Sensor Id"
                      value={newSensorid}
                      onChange={(e) => {
                        const { value } = e.target;
                        setNewSensorid(value);
                      }}
                    />

                    <BasicTextFields
                      className="w-full rounded-md px-2 py-1"
                      label="New Hive Location"
                      value={newHiveLocation}
                      onChange={(e) => {
                        const { value } = e.target;
                        setNewHiveLocation(value);
                      }}
                    />

                    <div className="mt-4 flex justify-center">
                      <button
                        onClick={editHiveHandler}
                        className="rounded-full bg-green-500 px-5 py-3 text-base font-medium text-white transition duration-200 hover:bg-green-600 active:bg-green-700 dark:bg-green-400 dark:text-white dark:hover:bg-green-300 dark:active:bg-green-200"
                      >
                        SAVE
                      </button>
                    </div>
                  </div>
                ) : (
                  <span>{hiveName}</span>
                )}
              </div>
              {!IsEditButtenPresed && (
                <div className="flex flex-shrink-0 items-center justify-center rounded-full">
                  {healthStatus !== "No Data" ? (
                    <Tooltip title="Connected" arrow>
                      <SensorsIcon style={{ color: "green" }} />
                    </Tooltip>
                  ) : (
                    <Tooltip title="Disconnected" arrow>
                      <SensorsOffIcon style={{ color: "red" }} />
                    </Tooltip>
                  )}
                </div>
              )}
            </div>
            {/*    Id Field */}
            {IsEditButtenPresed ? null : (
              <p className="mt-1 text-sm font-medium text-gray-600 md:mt-0">
                id {id}
              </p>
            )}
          </div>
        </div>
{/* Temperature Field and other sensor data */}
<div className="flex flex-col space-y-2 md:flex-row md:flex-wrap md:items-center md:justify-between md:space-y-0">
  {/* Temperature Field */}
  {!IsEditButtenPresed && (
    <div className="flex">
      <p className="text-sm mb-2 font-bold text-red-500 dark:text-white">
        <DeviceThermostatIcon /> Temperature:{" "}
        {Temperature !== null ? (
          <span>{Temperature} °C</span>
        ) : (
          <span className="text-gray-500">Waiting for data...</span>
        )}
      </p>
    </div>
  )}

  {/* Humidity Field */}
  {!IsEditButtenPresed && (
    <div className="flex">
      <p className="text-sm mb-2 font-bold text-blue-500 dark:text-white">
        <WaterDropIcon /> Humidity:{" "}
        {Humidity !== null ? (
          <span>{Humidity} %</span>
        ) : (
          <span className="text-gray-500">Waiting for data...</span>
        )}
      </p>
    </div>
  )}

  {/* GPS Field */}
  {!IsEditButtenPresed && (
    <div className="text-grey-500 !mb-2 flex items-center text-sm font-bold dark:text-white">
      <MapIcon className="mr-1" />
      <span
        className={
          !isGpsCorrect
            ? "bg-red-50 rounded border border-red-500 inline-block"
            : "inline-block"
        }
      >
        {!sensorLocation ? (
          <span className="text-gray-500 italic">Waiting for GPS...</span>
        ) : isGpsCorrect ? (
          <span className="text-black">Verified: {sensorLocation}</span>
        ) : (
          <span className="text-red-700">
            <strong>Mismatch!</strong> You entered "
            <span className="underline">{Location}</span>
            ", but GPS detected "
            <span className="underline">{sensorLocation}</span>
            ".
          </span>
        )}
      </span>
      {Latitude && Longitude && (
        <Tooltip title="Real Time Location" arrow>
          <MdGpsFixed
            className={`ml-2 transition-colors duration-300 ${
              isRed ? "text-red-500" : "text-white"
            }`}
          />
        </Tooltip>
      )}
    </div>
  )}

  {/* STATE Field */}
  {!IsEditButtenPresed && (
    <div className="flex">
      <p className="text-sm mb-2 font-bold dark:text-white">
        {healthStatus === "Healthy" ? (
          <span className="text-green-500">
            <GppGoodIcon /> State: Healthy
          </span>
        ) : healthStatus === "Unhealthy" ? (
          <span className="text-orange-500">
            <GppBadIcon /> State: Unhealthy
          </span>
        ) : (
          <span className="text-gray-500">
            <GppMaybeIcon /> State: No Data
          </span>
        )}
      </p>
    </div>
  )}

  {/* Last Data Received Field */}
  {!IsEditButtenPresed && (
    <p className="text-sm font-medium text-gray-600 md:mt-0">
      Last data {lastDataR}
    </p>
  )}
</div>
      </div>
    </Card>
  );
};

export default HiveCard;

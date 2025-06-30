import React, { useEffect, useState } from "react";
import HiveCard from "./components/HiveCard.jsx";
import AddHiveArea from "./components/AddHiveArea.jsx";
import BEE1 from "assets/img/beehive/bee5.jpg";
import Ebee from "assets/img/beehive/emptybee.png";
import AddHiveButton from "./components/AddHiveButton.jsx";
import Alert from "@mui/material/Alert";
import HivesSummary from "./components/HivesSummary.jsx";
import { useNavigate } from "react-router-dom"; // Import useNavigate

const AllHives = () => {
  const navigate = useNavigate(); // Initialize navigate function
  const [isGPSCorrect, setIsGPSCorrect] = useState(true);
  const [hiveWorngGps, setHiveWorngGps] = useState([]);
  const [listOfHives, setlistOfHives] = useState([]);
  const [isSlideclicked, setSladeState] = useState(false);
  const [isHiveAdded, setisHiveAdded] = useState(false);
  const [isSensorIdNull, setIsSensorIdNull] = useState(false);
  const [isSensorIdAlreadyExist, setIsSensorIdAlreadyExist] = useState(false);
  const [isHiveModified, setIsHiveModified] = useState(false);
  const [isLoading, setIsLoading] = useState(true); // Add loading state
  const [controllerBatteryVoltage, setcontrollerBatteryVoltage] = useState(); // Add loading state
  const [healthCounts, setHealthCounts] = useState({
    healthy: 0,
    unhealthy: 0,
    noData: 0,
  });

  const updateHealthCounts = (status) => {
    setHealthCounts((prev) => {
      const newCounts = { ...prev };
      if (status === "Healthy") newCounts.healthy += 1;
      else if (status === "Unhealthy") newCounts.unhealthy += 1;
      else newCounts.noData += 1;
      return newCounts;
    });
  };

  /////// Fetch All Hives useEffect when a load the page and repete it every 2s////////
  useEffect(() => {
    const fetchHives = async () => {
      try {
        setIsLoading(true); // Start loading
        const response = await fetch(
          `${process.env.REACT_APP_API_URL}/admin/getAllHives`,
          {
            credentials: "include",
            headers: {
              "Cache-Control": "no-cache",
              Pragma: "no-cache",
            },
          }
        );

        if (response.status === 401) {
          navigate("/auth/sign-in"); // Redirect immediately if unauthorized
          return;
        }

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        setlistOfHives(data);
      } catch (error) {
        console.error("Error fetching data:", error);
        if (error.message === "Failed to fetch") {
          console.log("Network error - server might be down");
        }
      } finally {
        setIsLoading(false); // Stop loading (even if error occurs)
      }
    };

    fetchHives(); // Initial load

    //const interval = setInterval(fetchHives, 1000);
    //return () => clearInterval(interval); // Cleanup on unmount
  }, [navigate]);

  ///////////// notification area /////////////////
  useEffect(() => {
    if (isHiveAdded) {
      const timer = setTimeout(() => {
        setisHiveAdded(false); // Hide the alert after 3 seconds
      }, 2000);

      return () => clearTimeout(timer); // Cleanup on unmount
    }
  }, [isHiveAdded]); // Run effect when `isHiveAdded` changes
  useEffect(() => {
    if (isSensorIdNull) {
      const timer = setTimeout(() => {
        setIsSensorIdNull(false); // Hide the alert after 3 seconds
      }, 2000);

      return () => clearTimeout(timer); // Cleanup on unmount
    }
  }, [isSensorIdNull]); // Run effect when `isHiveAdded` changes
  useEffect(() => {
    if (isSensorIdAlreadyExist) {
      const timer = setTimeout(() => {
        setIsSensorIdAlreadyExist(false); // Hide the alert after 3 seconds
      }, 2000);

      return () => clearTimeout(timer); // Cleanup on unmount
    }
  }, [isSensorIdAlreadyExist]); // Run effect when `isHiveAdded` changes
  useEffect(() => {
    if (isHiveModified) {
      const timer = setTimeout(() => {
        setIsHiveModified(false); // Hide the alert after 3 seconds
      }, 2000);

      return () => clearTimeout(timer); // Cleanup on unmount
    }
  }, [isHiveModified]); // Run effect when `isHiveAdded` changes
  ///////////// END Notification area /////////////////

  function sliderHandler() {
    setSladeState(!isSlideclicked);
  }
  async function AddHiveHandler(newHive) {
    /////////// check if sensor id empty ///////////////
    if (!newHive.sensorId || newHive.sensorId.trim() === "") {
      setIsSensorIdNull(true);
      console.log("Sensor ID cannot be empty");
      return;
    }
    ////////////////////////////////////////////////////

    /////////// adding hive query ///////////////
    try {
      const response = await fetch(
        `${process.env.REACT_APP_API_URL}/admin/add-hive`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(newHive),
        }
      );
      ////////////////////////////////////////////////////

      /////////// check if sensor id already existe ///////////////

      const result = await response.json();

      if (!response.ok) {
        // Check if error is about existing sensor ID
        if (result.error && result.error.includes("Database error")) {
          setIsSensorIdAlreadyExist(true);
        }
        throw new Error(result.error || "Failed to add hive");
      }
      // If we get here, the hive was added successfully
      console.log("Hive added successfully:", result);
      setisHiveAdded(true); // Show success alert

      ////////////////////////////////////////////////////

      /////////// refetch hives after adding ///////////////
      const fetchHives = async () => {
        try {
          const response = await fetch(
            `${process.env.REACT_APP_API_URL}/admin/getAllHives`,
            {
              credentials: "include", // ← IMPORTANT
              headers: {
                "Cache-Control": "no-cache",
                Pragma: "no-cache",
              },
            }
          );
          const data = await response.json();
          setlistOfHives(data);
          console.log(listOfHives);
        } catch (err) {
          console.error("Error fetching data:", err);
        }
      };
      await fetchHives();
    } catch (error) {
      console.error("Error adding hive:", error);
      // You might want to show an error alert here
    }
  }
  /// set the allert of GPS ////
  function GpsErrorHandler(id, hiveName, isCorrect) {
    if (!isCorrect) {
      console.log("GPS error from sensor => " + id + " hive name: " + hiveName);
      setIsGPSCorrect(false);
      setHiveWorngGps((prevValue) => {
        const alreadyExists = prevValue.some((hive) => hive.id === id);
        if (alreadyExists) return prevValue;
        return [...prevValue, { id, hiveName }];
      });
    } else {
      // GPS is now correct → remove hive from error list
      console.log("GPS corrected for hive: " + hiveName);
      setIsGPSCorrect(true);
      setHiveWorngGps((prevValue) =>
        prevValue.filter((hive) => hive.id !== id)
      );
    }
  }
  const formatTimestamp = (isoString) => {
    const date = new Date(isoString);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    const hours = String(date.getHours()).padStart(2, "0");
    const minutes = String(date.getMinutes()).padStart(2, "0");

    return `${year}-${month}-${day} ${hours}:${minutes}`;
  };
  ////// hive card edir sensor id empty ////
  function editWarnnigHandler(e) {
    if (e === "Sensor ID already exists.") {
      setIsSensorIdAlreadyExist(true);
    }
    if (e === "Sensor ID cannot be empty.") {
      setIsSensorIdNull(true);
    }
    if (e === "Hive updated data received successfully") {
      setIsHiveModified(true);
    }
  }
  ///// update hives card after editing ////////
  const updateHivesCard = async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_API_URL}/admin/getAllHives`,
        {
          credentials: "include",
          headers: {
            "Cache-Control": "no-cache",
            Pragma: "no-cache",
          },
        }
      );
      const data = await response.json();
      setlistOfHives(data);
      editWarnnigHandler("Hive updated data received successfully");
    } catch (err) {
      console.error("Error fetching data:", err);
    }
  };
  /**/
  if (isLoading) {
    return;
  }
  return (
    <div>
      <div>
        {hiveWorngGps.length > 0 ? (
          <Alert variant="filled" severity="error" className="mt-3">
            GPS Error in hive(s):{" "}
            {hiveWorngGps
              .map((hive) => `${hive.hiveName} (ID: ${hive.id})`)
              .join(", ")}
          </Alert>
        ) : null}
      </div>

      <div className="mt-5 flex items-center justify-center">
        <HivesSummary
          totalHive={listOfHives.length}
          healthyHives={healthCounts.healthy}
          unhealthyHives={healthCounts.unhealthy}
          noDataHives={healthCounts.noData}
          controllerBatteryVoltage={
            listOfHives.length > 0 && listOfHives[0].battery_voltage != null
              ? listOfHives[0].battery_voltage
              : 0
          }
          //lon={listOfHives ? listOfHives[0].longitude: null}
          //lat={listOfHives ? listOfHives[0].latitude : null}
        />
      </div>

      <AddHiveButton sliderHandler={sliderHandler} />
      {isSlideclicked ? <AddHiveArea AddHive={AddHiveHandler} /> : null}
      {isHiveAdded ? (
        <Alert variant="filled" severity="success">
          Hive Added Succesfuly.
        </Alert>
      ) : null}
      {isSensorIdNull ? (
        <Alert variant="filled" severity="warning">
          Sensor Id Cannot Be Empty !
        </Alert>
      ) : null}
      {isSensorIdAlreadyExist ? (
        <Alert variant="filled" severity="info">
          Sensor Id Already Exist !
        </Alert>
      ) : null}
      {isHiveModified ? (
        <Alert variant="filled" severity="success">
          Hive Modified Succesfuly.
        </Alert>
      ) : null}
      {listOfHives.length >0 ? <div className="z-20 grid grid-cols-1 gap-5 md:grid-cols-4">
        {listOfHives.map((hive, index) => (
          <HiveCard
            key={index}
            id={hive.id}
            hiveName={hive.hiveName}
            image={
              hive.image_url
                ? `${process.env.REACT_APP_API_URL}${hive.image_url}`
                : BEE1
            }
            Temperature={hive.temperature}
            Humidity={hive.humidity}
            Location={hive.location} //
            Longitude={hive.longitude} //
            Latitude={hive.latitude} //
            lastDataR={formatTimestamp(hive.lastDataR)}
            onHealthStatusChange={updateHealthCounts}
            GpsErrorHandler={GpsErrorHandler}
            editWarnnigHandler={editWarnnigHandler}
            updateHivesCard={updateHivesCard}
            link="detailed-dashboard"
          />
        ))}
      </div>: (
  <div className="flex flex-col items-center justify-center py-12 text-center">
    {/* Ebee image with subtle hover effect */}
    <img 
      src={Ebee}  // Update with your actual image path
      alt="Empty hive illustration"
      className="w-40 h-40 mb-4 object-contain hover:scale-105 transition-transform"
    />
      <path 
        strokeLinecap="round" 
        strokeLinejoin="round" 
        strokeWidth="1.5" 
        d="M12 4v16m8-8H4m13-5l-5 5m5 5l-5-5m-5-5l5 5m-5 5l5-5"
      />
    <h3 className="text-xl font-medium text-gray-700 mb-2">
      Please Insert Your First Hive
    </h3>
    <p className="text-gray-500 max-w-md px-4">
      No hives are currently registered. When you add your first hive, you'll see its health metrics, location data, and monitoring information displayed here.
    </p>
  </div>
)}
    </div>
  );
};

export default AllHives;

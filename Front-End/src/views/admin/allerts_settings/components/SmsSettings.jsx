import React, { useEffect, useState } from "react";
import CardMenu from "components/card/CardMenu";
import Card from "components/card";
import { FaSms } from "react-icons/fa";
import { FaTemperatureHigh } from "react-icons/fa";
import { WiHumidity } from "react-icons/wi";
import { GiWeight } from "react-icons/gi";
import { useNavigate } from 'react-router-dom'; 
import { MapContainer, TileLayer, Marker, useMapEvents } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import { useMap } from "react-leaflet";

function SmsAlertsTable(props) {
  const [smsEnabled, setSmsEnabled] = useState();
  const [tempMin, setTempMin] = useState();
  const [tempMax, setTempMax] = useState();
  const [humidityMin, setHumidityMin] = useState();
  const [humidityMax, setHumidityMax] = useState();
  const [weightMin, setWeightMin] = useState();
  const [weightMax, setWeightMax] = useState();
  const [searchQuery, setSearchQuery] = useState("");
const [refLat, setRefLat] = useState(35.5024); // default latitude
const [refLng, setRefLng] = useState(11.0457); // default longitude
// Fix default marker icon issue
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});
function MapCenterUpdater({ lat, lng }) {
  const map = useMap();

  useEffect(() => {
    if (lat && lng) {
      map.flyTo([lat, lng], map.getZoom()); // or map.setView(...)
    }
  }, [lat, lng, map]);

  return null;
}

function LocationPicker({ setLat, setLng }) {
  useMapEvents({
    click(e) {
      setLat(e.latlng.lat);
      setLng(e.latlng.lng);
    },
  });
  return null;
}


const navigate = useNavigate();
useEffect(() => {
  const fetchSettings = async () => {
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/api/sms-alert-settings`, {
          credentials: "include",
          headers: {
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
          },
        });
      const data = await response.json();

        if (response.status === 401) {
        navigate('/auth/sign-in'); // Redirect if unauthorized
        return;
      }
       if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      setTempMin(data.MIN_TEMP);
      setTempMax(data.MAX_TEMP);
      setHumidityMin(data.MIN_HUMIDITY);
      setHumidityMax(data.MAX_HUMIDITY);
      setWeightMin(data.MIN_WEIGHT);
      setWeightMax(data.MAX_WEIGHT);
      setSmsEnabled(data.isAlertsON);
      setRefLat(data.REFERENCE_LATITUDE ?? 35.5024);
      setRefLng(data.REFERENCE_LONGITUDE ?? 11.0457);
    } catch (error) {
      console.error("Failed to fetch alert settings:", error);
      // You can optionally leave the default values as-is here
    }
  };

  fetchSettings();
}, [navigate]);

const handleSave = async () => {
  try {
    const response = await fetch(
      `${process.env.REACT_APP_API_URL}/api/update_alert-config`,
      {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
        },
        body: JSON.stringify({
          MIN_TEMP: tempMin,
          MAX_TEMP: tempMax,
          MIN_HUMIDITY: humidityMin,
          MAX_HUMIDITY: humidityMax,
          MIN_WEIGHT: weightMin,
          MAX_WEIGHT: weightMax,
          isAlertsON: smsEnabled,
          REFERENCE_LATITUDE: refLat, 
          REFERENCE_LONGITUDE: refLng,  
        }),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Failed to save settings");
    }

    console.log("API Response:", data);
    alert("Settings saved successfully!");
  } catch (error) {
    console.error("Failed to save settings:", error);
    alert(error.message || "Failed to save settings. Please try again.");
  }
};
const handleSearchKey = async (e) => {
  if (e.key === "Enter" && searchQuery.trim() !== "") {
    try {
      const response = await fetch(
        `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(
          searchQuery
        )}&format=json&limit=1`
      );
      const data = await response.json();
      if (data && data.length > 0) {
        const result = data[0];
        setRefLat(parseFloat(result.lat));
        setRefLng(parseFloat(result.lon));
      } else {
        alert("Location not found");
      }
    } catch (err) {
      console.error("Geocoding error:", err);
      alert("Error searching location");
    }
  }
};
  return (
    <Card extra={"w-full h-full sm:overflow-auto px-6"}>
      <header className="relative flex items-center justify-between pt-4">
        <div className="flex items-center gap-2 text-xl font-bold text-navy-700 dark:text-white">
          SMS Alerts Settings <FaSms />
        </div>
        <CardMenu />
      </header>

      <div className="mt-8">
        {/* SMS Notification Switch */}
        <div className="mb-4 flex items-center justify-between rounded-lg bg-gray-100 p-4 dark:bg-gray-800">
          <div className="flex items-center">
            <span className="mr-3 text-sm font-medium text-gray-700 dark:text-gray-300">
              Enable SMS Notification
            </span>
            <label className="relative inline-flex cursor-pointer items-center">
              <input
                type="checkbox"
                className="peer sr-only"
                checked={smsEnabled}
                onChange={() => setSmsEnabled(!smsEnabled)}
              />
              <div className="peer h-6 w-11 rounded-full bg-gray-200 after:absolute after:left-[2px] after:top-[2px] after:h-5 after:w-5 after:rounded-full after:border after:border-gray-300 after:bg-white after:transition-all after:content-[''] peer-checked:bg-green-600 peer-checked:after:translate-x-full peer-checked:after:border-white peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:border-gray-600 dark:bg-gray-700 dark:peer-focus:ring-blue-800"></div>
            </label>
          </div>
        </div>

        {/* Threshold Settings Table */}
        <div className="overflow-x-scroll xl:overflow-x-hidden">
          <table className="w-full">
            <thead>
              <tr className="!border-px !border-gray-400">
                <th className="cursor-pointer border-b-[1px] border-gray-200 pb-2 pr-4 pt-4 text-start">
                  <div className="items-center justify-between text-xs text-gray-200">
                    Parameter
                  </div>
                </th>
                <th className="cursor-pointer border-b-[1px] border-gray-200 pb-2 pr-4 pt-4 text-start">
                  <div className="items-center justify-between text-xs text-gray-200">
                    Min Threshold
                  </div>
                </th>
                <th className="cursor-pointer border-b-[1px] border-gray-200 pb-2 pr-4 pt-4 text-start">
                  <div className="items-center justify-between text-xs text-gray-200">
                    Max Threshold
                  </div>
                </th>
              </tr>
            </thead>
            <tbody>
              {/* Temperature Row */}
              <tr>
                <td className="ml-0 flex min-w-[150px] items-center gap-2 border-white/0 py-3 pr-4 font-medium text-red-600 dark:text-red-400">
                  <FaTemperatureHigh className="text-xl" /> Temperature
                </td>{" "}
                <td className="min-w-[150px] border-white/0 py-3 pr-4">
                  <input
                    type="number"
                    value={tempMin}
                    onChange={(e) => setTempMin(Number(e.target.value))}
                    className="w-16 rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
                  />{" "}
                  °C
                </td>
                <td className="min-w-[150px] border-white/0 py-3 pr-4">
                  <input
                    type="number"
                    value={tempMax}
                    onChange={(e) => setTempMax(Number(e.target.value))}
                    className="w-16 rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
                  />{" "}
                  °C
                </td>
              </tr>

              {/* Humidity Row */}
              <tr>
                <td className="flex min-w-[150px] items-center gap-2 border-white/0 py-3 pr-4 font-medium text-blue-600 dark:text-blue-400">
                  <WiHumidity className="text-2xl" /> Humidity
                </td>
                <td className="min-w-[150px] border-white/0 py-3 pr-4">
                  <input
                    type="number"
                    value={humidityMin}
                    onChange={(e) => setHumidityMin(Number(e.target.value))}
                    className="w-16 rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
                  />{" "}
                  %
                </td>
                <td className="min-w-[150px] border-white/0 py-3 pr-4">
                  <input
                    type="number"
                    value={humidityMax}
                    onChange={(e) => setHumidityMax(Number(e.target.value))}
                    className="w-16 rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
                  />{" "}
                  %
                </td>
              </tr>

              {/* Weight Row */}
              <tr>
                <td className="flex min-w-[150px] items-center gap-2 border-white/0 py-3 pr-4 font-medium text-green-600 dark:text-green-400">
                  <GiWeight className="text-xl" /> Weight
                </td>
                <td className="min-w-[150px] border-white/0 py-3 pr-4">
                  <input
                    type="number"
                    value={weightMin}
                    onChange={(e) => setWeightMin(Number(e.target.value))}
                    className="w-16 rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
                  />{" "}
                  Kg
                </td>
                <td className="min-w-[150px] border-white/0 py-3 pr-4">
                  <input
                    type="number"
                    value={weightMax}
                    onChange={(e) => setWeightMax(Number(e.target.value))}
                    className="w-16 rounded border border-gray-300 px-2 py-1 text-sm dark:border-gray-700 dark:bg-gray-800"
                  />{" "}
                  Kg
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        {/* GPS Settigns */}
        <div className="mb-6">
<div className="mb-2 flex items-center gap-2">
  <h4 className="font-semibold text-gray-700 dark:text-gray-300 whitespace-nowrap">
    Select GPS Reference Location
  </h4>
  <input
    type="text"
    placeholder="Search city or place..."
    value={searchQuery}
    onChange={(e) => setSearchQuery(e.target.value)}
    onKeyDown={handleSearchKey}
    className="w-64 rounded border border-gray-300 px-3 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-white"
  />
</div>
  <div className="h-64 w-full rounded shadow">
    <MapContainer
      center={[refLat, refLng]}
      zoom={13}
      style={{ height: "100%", width: "100%" }}
    >
      <TileLayer
        attribution='&copy; OpenStreetMap contributors'
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
      />
        <MapCenterUpdater lat={refLat} lng={refLng} /> 
      <LocationPicker setLat={setRefLat} setLng={setRefLng} />
      <Marker position={[refLat, refLng]} />
    </MapContainer>
  </div>
 <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
  Selected Location:{" "}
  <strong>
    {refLat != null ? refLat.toFixed(6) : "N/A"},{" "}
    {refLng != null ? refLng.toFixed(6) : "N/A"}
  </strong>
</p>
</div>

        {/* Centered Save Button */}
        <div className="mb-5 mt-6 flex justify-center">
          <button
            onClick={handleSave}
            className="rounded-lg bg-blue-600 px-6 py-2 text-sm font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-300 dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800"
          >
            Save Settings
          </button>
        </div>
      </div>
    </Card>
  );
}

export default SmsAlertsTable;

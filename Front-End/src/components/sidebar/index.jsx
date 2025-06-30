/* eslint-disable */
import React, { useState, useEffect } from "react";
import { HiX } from "react-icons/hi";
import Links from "./components/Links";
import routes from "routes.js";
import WeatherWidget from "./components/WeatherCard";
import bee from "assets/img/layout/bee (1).png"
const Sidebar = ({ open, onClose }) => {
  const [lon, setLon] = useState("0");
  const [lat, setLat] = useState("0");

  useEffect(() => {
    const fetchLonLat = async () => {
      try {
        const response = await fetch("http://localhost:5000/admin/getAllHives", {
          credentials: "include", // Required for session cookies
        });
        const data = await response.json();
        setLon(data[0].longitude);
        setLat(data[0].latitude);
      } catch (err) {
        console.error("Error fetching data:", err);
      }
    };

    fetchLonLat(); // initial load

  }, []);
  
  return (
    <div
      className={`sm:none duration-175 linear fixed !z-50 flex min-h-full flex-col bg-white pb-10 shadow-2xl shadow-white/5 transition-all dark:!bg-navy-800 dark:text-white md:!z-50 lg:!z-50 xl:!z-0 ${
        open ? "translate-x-0" : "-translate-x-96"
      }`}
    >
      <span
        className="absolute right-4 top-4 block cursor-pointer xl:hidden"
        onClick={onClose}
      >
        <HiX />
      </span>

      <div className={`mx-[56px] mt-[50px] flex items-center`}>
        <div className="ml-1 mt-1 h-2.5 font-poppins text-[26px] font-bold uppercase text-navy-700 dark:text-white">
          BeeTrack <img src={bee} alt="Bee Icon" className="inline w-6 h-6 mx-1" /><span class="font-medium"></span>
        </div>
      </div>
      <div class="mb-7 mt-[58px] h-px bg-gray-300 dark:bg-white/30" />
      {/* Nav item */}

      <ul className="mb-auto pt-1">
        <Links routes={routes} />
        {/* Weather Widget */}
        {lon !== "0" && lat !== "0" && (
          <div className="mt-3 p-4">
            <WeatherWidget lon={lon} lat={lat} />
          </div>
        )}
      </ul>

      {/* Nav item end */}
    </div>
  );
};

export default Sidebar;

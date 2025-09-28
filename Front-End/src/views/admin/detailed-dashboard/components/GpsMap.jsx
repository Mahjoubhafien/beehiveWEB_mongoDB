import React, { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

import markerIcon from 'leaflet/dist/images/marker-icon.png';
import markerIcon2x from 'leaflet/dist/images/marker-icon-2x.png';
import markerShadow from 'leaflet/dist/images/marker-shadow.png';

const MapComponent = ({ lat, lng }) => {
  const mapRef = useRef(null);
  const markerRef = useRef(null);

  useEffect(() => {
    if (lat == null || lng == null) {
      return;
    }

    // Initialize map once
    if (!mapRef.current) {
      mapRef.current = L.map("map").setView([lat, lng], 13);

      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png").addTo(mapRef.current);
    } else {
      // Update view if map already initialized
      mapRef.current.setView([lat, lng], 13);
    }

    // Marker icon setup
    const defaultIcon = L.icon({
      iconUrl: markerIcon,
      iconRetinaUrl: markerIcon2x,
      shadowUrl: markerShadow,
      iconSize: [25, 41],
      iconAnchor: [12, 41],
      popupAnchor: [1, -34],
      shadowSize: [41, 41],
    });

    // Remove old marker if exists
    if (markerRef.current) {
      markerRef.current.remove();
    }

    // Add new marker
    markerRef.current = L.marker([lat, lng], { icon: defaultIcon }).addTo(mapRef.current);

    // Cleanup on unmount
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [lat, lng]);

  return (
    <div id="map" style={{ height: "400px", width: "100%" }} />
  );
};

export default MapComponent;

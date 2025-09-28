const GpsMap = () => {
  return (
    <iframe 
  width="400" 
  height="300" 
  frameborder="0" 
  src="https://www.openstreetmap.org/export/embed.html?bbox=YOUR_LONGITUDE%2CYOUR_LATITUDE%2CYOUR_LONGITUDE%2CYOUR_LATITUDE&layer=mapnik&marker=YOUR_LATITUDE%2CYOUR_LATITUDE">
</iframe>
  );
};

export default GpsMap;

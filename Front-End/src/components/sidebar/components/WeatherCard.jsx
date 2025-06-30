import React, { useState, useEffect, useRef } from 'react';
const WeatherIcons = {
  wind: '💨',
  humidity: '💧',
  rain: '🌧️',
  thermometer: '🌡️',
  chevron: '➜'
};

const WeatherWidget = ({ lat, lon, api_key = "e21f2b6fce3340dc9ba143227252805" }) => {
  const [weather, setWeather] = useState(null);
  const [forecast, setForecast] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [weatherLocation, setWeatherLocation] = useState();
  const [showForecast, setShowForecast] = useState(false);
  const containerRef = useRef(null);

  // Get location name
  useEffect(() => {
    console.log("weatherCard");
    const fetchLocation = async () => {
      try {
        const response = await fetch(
          `http://localhost:5000/admin/getHiveLocation?latitude=${lat}&longitude=${lon}`
        );
        const locationData = await response.json();
        setWeatherLocation(locationData.city);
      } catch(err) {
        console.log(err);
      }
    };

    if (lat && lon) fetchLocation();
  }, [lat, lon]);

  // Get weather data
  useEffect(() => {
    const fetchWeather = async () => {
      if (!lat || !lon) return;

      try {
        setLoading(true);
        setError(null);
        const query = `${lat},${lon}`;
        
        const response = await fetch(
          `https://api.weatherapi.com/v1/forecast.json?key=${api_key}&q=${query}&days=2`
        );
        const data = await response.json();
        
        setWeather({
          ...data.current,
          // Add chance of rain from forecast for current day
          chance_of_rain: data.forecast.forecastday[0]?.day?.daily_chance_of_rain || 0
        });
        setForecast(data.forecast.forecastday[1]);
        setLoading(false);
      } catch (error) {
        console.error("Failed to fetch weather:", error);
        setError(error);
        setLoading(false);
      }
    };

    fetchWeather();
  }, [lat, lon, api_key]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error fetching weather</div>;
  if (!weather) return <div>No weather data available</div>;

return (
    <div 
      style={{ 
        width: '240px',
        fontFamily: "'Segoe UI', Roboto, sans-serif",
        borderRadius: '12px',
        boxShadow: '0 3px 10px rgba(0, 0, 0, 0.15)',
        overflow: 'hidden',
        backgroundColor: '#f8fafc', // Slightly off-white background
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        border: '1px solid #e2e8f0' // Subtle border for contrast
      }}
      onClick={() => setShowForecast(!showForecast)}
    >
      {/* Current Weather */}
      {!showForecast && (
        <div style={{ padding: '16px', backgroundColor: '#ffffff', borderRadius: '12px 12px 0 0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ 
              margin: 0, 
              fontSize: '15px', 
              fontWeight: 600,
              color: '#1e293b', // Darker text for contrast
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              maxWidth: '160px'
            }}>
              {weatherLocation || "Fetching Location..."}
            </h3>
            <img 
              src={`https:${weather.condition.icon}`} 
              alt={weather.condition.text}
              style={{ width: '42px', height: '42px', filter: 'drop-shadow(1px 1px 2px rgba(0,0,0,0.1))' }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', margin: '12px 0' }}>
            <span style={{ fontSize: '32px', fontWeight: 500, color: '#1e40af' }}>{weather.temp_c}°</span>
            <div style={{ marginLeft: '12px' }}>
              <p style={{ margin: '3px 0', fontSize: '13px', color: '#334155' }}>
                {weather.condition.text}
              </p>
              <p style={{ margin: '3px 0', fontSize: '13px', color: '#64748b' }}>
                {WeatherIcons.thermometer} H: {forecast?.day.maxtemp_c}° L: {forecast?.day.mintemp_c}°
              </p>
            </div>
          </div>

          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(3, 1fr)', 
            gap: '10px',
            fontSize: '12px',
            borderTop: '1px solid #f1f5f9',
            paddingTop: '10px'
          }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '16px', marginBottom: '2px' }}>{WeatherIcons.wind}</div>
              <p style={{ margin: 0, color: '#64748b' }}>Wind</p>
              <p style={{ margin: 0, fontWeight: 500 }}>{weather.wind_kph} km/h</p>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '16px', marginBottom: '2px' }}>{WeatherIcons.humidity}</div>
              <p style={{ margin: 0, color: '#64748b' }}>Humidity</p>
              <p style={{ margin: 0, fontWeight: 500 }}>{weather.humidity}%</p>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '16px', marginBottom: '2px' }}>{WeatherIcons.rain}</div>
              <p style={{ margin: 0, color: '#64748b' }}>Rain</p>
              <p style={{ margin: 0, fontWeight: 500 }}>{weather.chance_of_rain}%</p>
            </div>
          </div>
        </div>
      )}

      {/* Tomorrow's Forecast */}
      {showForecast && (
        <div style={{ 
          padding: '16px', 
          backgroundColor: '#ffffff',
          borderRadius: '12px 12px 0 0',
          height: '100%'
        }}>
          <h3 style={{ 
            margin: '0 0 12px 0', 
            fontSize: '15px', 
            fontWeight: 600,
            color: '#1e293b',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis'
          }}>
            Tomorrow in {weatherLocation}
          </h3>
          
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '12px' }}>
            <img 
              src={`https:${forecast?.day.condition.icon}`} 
              alt={forecast?.day.condition.text}
              style={{ width: '42px', height: '42px', filter: 'drop-shadow(1px 1px 2px rgba(0,0,0,0.1))' }}
            />
            <div style={{ marginLeft: '12px' }}>
              <p style={{ margin: '3px 0', fontSize: '13px', color: '#334155' }}>
                {forecast?.day.condition.text}
              </p>
              <p style={{ margin: '3px 0', fontSize: '28px', fontWeight: 500, color: '#1e40af' }}>
                {forecast?.day.avgtemp_c}°
              </p>
            </div>
          </div>

          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(3, 1fr)', 
            gap: '10px',
            fontSize: '12px',
            borderTop: '1px solid #f1f5f9',
            paddingTop: '10px'
          }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '16px', marginBottom: '2px' }}>↑</div>
              <p style={{ margin: 0, color: '#64748b' }}>High</p>
              <p style={{ margin: 0, fontWeight: 500 }}>{forecast?.day.maxtemp_c}°</p>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '16px', marginBottom: '2px' }}>↓</div>
              <p style={{ margin: 0, color: '#64748b' }}>Low</p>
              <p style={{ margin: 0, fontWeight: 500 }}>{forecast?.day.mintemp_c}°</p>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '16px', marginBottom: '2px' }}>{WeatherIcons.rain}</div>
              <p style={{ margin: 0, color: '#64748b' }}>Rain</p>
              <p style={{ margin: 0, fontWeight: 500 }}>{forecast?.day.daily_chance_of_rain}%</p>
            </div>
          </div>
        </div>
      )}

      {/* Toggle Footer */}
      <div style={{
        padding: '10px 16px',
        backgroundColor: showForecast ? '#e0f2fe' : '#f0fdf4',
        textAlign: 'center',
        fontSize: '12px',
        color: '#334155',
        borderTop: '1px solid #e2e8f0',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '6px'
      }}>
        {showForecast ? (
          <>
            <span style={{ fontSize: '14px' }}>←</span>
            <span>Current Weather</span>
          </>
        ) : (
          <>
            <span>Tomorrow's Forecast</span>
            <span style={{ fontSize: '14px' }}>→</span>
          </>
        )}
      </div>
    </div>
  );
};

export default WeatherWidget;
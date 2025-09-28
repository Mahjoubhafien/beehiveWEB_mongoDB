
import Paper from '@mui/material/Paper';
import { styled } from '@mui/material/styles';

const BatteryIndicator = ({ voltage }) => {
  const maxVoltage = 4.2;   // fully charged 3.7V lithium
  const minVoltage = 3.0;   // low battery threshold

  const Item = styled(Paper)(({ theme }) => ({
    backgroundColor: "#fff",
    ...theme.typography.body2,
    padding: theme.spacing(1),
    textAlign: "center",
    color: (theme.vars ?? theme).palette.text.secondary,
    ...theme.applyStyles("dark", {
      backgroundColor: "#1A2027",
    }),
  }));
  
  // Clamp voltage within expected range
  const clampedVoltage = Math.max(minVoltage, Math.min(voltage, maxVoltage));

  // Calculate battery level percentage
  const level = ((clampedVoltage - minVoltage) / (maxVoltage - minVoltage)) * 100;

  // Determine bar color
  let barColor = "#4caf50"; // green
  if (level < 20) barColor = "#f44336"; // red
  else if (level < 50) barColor = "#ff9800"; // orange

  return (
    <Item style={{ backgroundColor: "#f9f9f9", color: "#333", display: "flex", alignItems: "center", gap: "12px" }}>
      <div style={{ width: "60px", height: "24px", border: "2px solid #333", borderRadius: "4px", position: "relative", background: "#eee" }}>
        <div
          style={{
            width: `${level}%`,
            height: "100%",
            backgroundColor: barColor,
            borderRadius: "2px",
            transition: "width 0.3s"
          }}
        ></div>
        {/* Battery tip */}
        <div
          style={{
            position: "absolute",
            right: "-6px",
            top: "6px",
            width: "4px",
            height: "12px",
            backgroundColor: "#333",
            borderRadius: "1px"
          }}
        ></div>
      </div>
      <span style={{ fontWeight: "bold", fontSize: "14px" }}>
        {voltage ? `${voltage.toFixed(2)} V` : "Not Connected"}
      </span>
    </Item>
  );
};
export default BatteryIndicator;

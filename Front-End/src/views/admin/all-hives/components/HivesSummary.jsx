import { useState, useEffect } from "react";
import Divider from "@mui/material/Divider";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import { styled } from "@mui/material/styles";
import GpsMap from "./GpsMap.jsx";
import { MdGpsFixed, MdWbSunny, MdWaterDrop, MdAir } from "react-icons/md";
import BatteryIndicator from './BatteryBar.jsx';

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


function HivesSummary(props) {

  return (
    <div>
      <Stack
        direction="row"
        divider={<Divider orientation="vertical" flexItem />}
        spacing={2}
      >
        <Item style={{ backgroundColor: "#1976d2", color: "white" }}>
          Total Hives{" "}
          <span style={{ fontWeight: "bold" }}>{props.totalHive}</span>
        </Item>
        <Item style={{ backgroundColor: "#2e7d32", color: "white" }}>
          Healthy Hives{" "}
          <span style={{ fontWeight: "bold" }}>{props.healthyHives}</span>
        </Item>
        <Item style={{ backgroundColor: "#d32f2f", color: "white" }}>
          Unhealthy Hives{" "}
          <span style={{ fontWeight: "bold" }}>{props.unhealthyHives}</span>{" "}
        </Item>
        <Item style={{ backgroundColor: "#616161", color: "white" }}>
          No Data hives{" "}
          <span style={{ fontWeight: "bold" }}>{props.noDataHives}</span>
        </Item>
         {/* Updated Controller Battery */}
        <BatteryIndicator voltage={props.controllerBatteryVoltage} />
      </Stack>
    </div>
    
  );
}
export default HivesSummary;

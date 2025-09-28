import { useState, useEffect } from "react";
import Divider from "@mui/material/Divider";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import { styled } from "@mui/material/styles";
import BatteryIndicator from './BatteryBar.jsx';
import {  useMediaQuery,Accordion, AccordionSummary, AccordionDetails, Typography } from "@mui/material";
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

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

const isPhone = useMediaQuery("(max-width:600px)"); // phone breakpoint

  if (isPhone) {
    // On phones, show as accordion
    return (
      <Accordion>
        <AccordionSummary
          expandIcon={<ExpandMoreIcon />}
          aria-controls="hive-stats-content"
          id="hive-stats-header"
        >
          <Typography>Hive Info</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div>Total Hives: <strong>{props.totalHive}</strong></div>
            <div>Healthy Hives: <strong>{props.healthyHives}</strong></div>
            <div>Unhealthy Hives: <strong>{props.unhealthyHives}</strong></div>
            <div>No Data Hives: <strong>{props.noDataHives}</strong></div>
            <div>Battery: <strong>{props.controllerBatteryVoltage}V</strong></div>
          </div>
        </AccordionDetails>
      </Accordion>
    );
  }

  // On larger screens, keep horizontal Stack
  return (
    <Stack
      direction={{ xs: "column", sm: "row" }}
      divider={<Divider orientation="vertical" flexItem />}
      spacing={2}
    >
      <Item style={{ backgroundColor: "#1976d2", color: "white" }}>
        Total Hives <strong>{props.totalHive}</strong>
      </Item>
      <Item style={{ backgroundColor: "#2e7d32", color: "white" }}>
        Healthy Hives <strong>{props.healthyHives}</strong>
      </Item>
      <Item style={{ backgroundColor: "#d32f2f", color: "white" }}>
        Unhealthy Hives <strong>{props.unhealthyHives}</strong>
      </Item>
      <Item style={{ backgroundColor: "#616161", color: "white" }}>
        No Data Hives <strong>{props.noDataHives}</strong>
      </Item>
      <BatteryIndicator voltage={props.controllerBatteryVoltage} />
    </Stack>
  );
};
export default HivesSummary;

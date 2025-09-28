import * as React from 'react';
import { useTheme } from '@mui/material/styles';
import Box from '@mui/material/Box';
import OutlinedInput from '@mui/material/OutlinedInput';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import Chip from '@mui/material/Chip';
import { useNavigate } from 'react-router-dom';

const ITEM_HEIGHT = 48;
const ITEM_PADDING_TOP = 8;
const MenuProps = {
  PaperProps: {
    style: {
      maxHeight: ITEM_HEIGHT * 4.5 + ITEM_PADDING_TOP,
      width: 250,
    },
  },
};

function getStyles(name, personName, theme) {
  return {
    fontWeight:
      personName === name
        ? theme.typography.fontWeightMedium
        : theme.typography.fontWeightRegular,
  };
}

export default function SingleSelectChip(props) {
    // inside your component
const navigate = useNavigate();

  const theme = useTheme();
  const [personName, setPersonName] = React.useState('');

  const handleChange = async (event) => {
    const selectedId = event.target.value;
    setPersonName(selectedId);

    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/admin/update-current-sensor`, {
        credentials: "include",
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
        },
        body: JSON.stringify({ id: selectedId }),
      });

      if (!response.ok) {
        throw new Error('Failed to update current sensor ID');
      }

      const result = await response.json();
      console.log('Server response:', result);
      props.updateSensorDataFromSelect();
    } catch (error) {
      console.error('Error updating sensor ID:', error);
    }
  };

  return (
    <div className="!mt-1">
  <FormControl sx={{ m: 1, width: 300 }}>
    <InputLabel id="sensor-select-label">{props.currentSensorId}</InputLabel>
    <Select
      labelId="sensor-select-label"
      id="sensor-select"
      value={personName}
      onChange={handleChange}
      input={<OutlinedInput label="Sensor ID" />}
      renderValue={(selected) => <Chip label={selected} />}
      MenuProps={MenuProps}
    >
      {/* Sort the array before mapping */}
      {props.allSonsorsIds
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true })) // Numeric-aware sort
        .map((name) => (
          <MenuItem
            key={name}
            value={name}
            style={getStyles(name, personName, theme)}
          >
            {name}
          </MenuItem>
        ))}
    </Select>
  </FormControl>
</div>
  );
}

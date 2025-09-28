import * as React from 'react';
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';

export default function BasicTextFields({ className, label,value, onChange}) {
  return (
    <Box
      component="form"
      sx={{ '& > :not(style)': { m:0} }}
      className={`rounded-md px-2 py-1 text-sm ${className}`}
      noValidate
      autoComplete="off"
    >
      <TextField id="filled-basic" label={label} variant="filled" value={value} onChange={onChange} />
    </Box>
  );
}
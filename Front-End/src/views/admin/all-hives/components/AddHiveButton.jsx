import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import React, { useState } from "react";



function AddHiveButton(props){
    return (<button onClick={props.sliderHandler}
  className="mt-3 mb-3 linear flex flex-row items-center rounded-xl bg-gradient-to-br from-brandLinear to-blueSecondary px-5 py-3 text-base font-medium text-white transition duration-200 hover:shadow-lg hover:shadow-brand-500/50"
  data-ripple-light
>
  <KeyboardArrowDownIcon />
  Add Beehive
</button>);
}
export default AddHiveButton;
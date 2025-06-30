import React, { useState } from "react";
import TextField from "components/fields/TextField.jsx";
import AddIcon from "@mui/icons-material/Add";
import UploadIcon from '@mui/icons-material/Upload';
import Alert from '@mui/material/Alert';

function AddHiveArea(props) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState('');
  const [isPhotoSubmitted, setIsPhotoSubmitted] = useState(false);


  const [newHive, setNewHive] = useState({
    hiveName: "",
    hiveLocation: "",
    sensorId: "",
    photoUrl:"",
  });
  function textHandler(e) {
    const { id, value } = e.target;
    setNewHive((lastValue) => {
      return {
        ...lastValue,
        [id]: value,
      };
    });
  }
const UploadPhotoHandler = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setSelectedFile(file);

    // Create preview URL
    const reader = new FileReader();
    reader.onloadend = () => {
      setPreviewUrl(reader.result);
    };
    reader.readAsDataURL(file);
  };

  const handleSubmit = async () => {
    if (!selectedFile) return;

    const formData = new FormData();
    formData.append('photo', selectedFile);

    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL}/admin/upload`, {
        method: 'POST',
        body: formData,
        // Don't set Content-Type header - the browser will set it with the correct boundary
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      const data = await response.json();
      console.log('Upload successful:', data);
      setNewHive((lastValue) => {
      return {
        ...lastValue,
        photoUrl: data.filePath,
      };

    });
    setIsPhotoSubmitted(true);
      // Handle success (update UI, etc.)
    } catch (error) {
      console.error('Error uploading file:', error);
      // Handle error
    }
  };
  return (
    <div className="z-20 mb-5 grid grid-cols-1 gap-5 md:grid-cols-4">
      <TextField
        onChange={textHandler}
        label="Hive Name"
        placeholder="What is you hive name ?"
        id="hiveName"
        cols="10"
        rows="2"
        type="text"
        value={newHive.hiveName}
      />
      <TextField
        onChange={textHandler}
        label="Hive Location"
        placeholder="Where is you hive located ?"
        id="hiveLocation"
        cols="10"
        rows="2"
        type="text"
        value={newHive.hiveLocation}
      />
      <TextField
        onChange={textHandler}
        label="Sensor ID"
        placeholder="must be unique !"
        id="sensorId"
        cols="5"
        rows="2"
        type="number"
        value={newHive.sensorId}
      />
  
      <div className="mt-6 flex items-center justify-start">
         <div>
      <label className="mr-5 cursor-pointer rounded-xl bg-gradient-to-br from-brandLinear to-blueSecondary px-5 py-3 text-base font-medium text-white transition duration-200 hover:shadow-lg hover:shadow-blueSecondary/50">
        <input 
          type="file" 
          accept="image/*" 
          onChange={UploadPhotoHandler}
          className="hidden"
        />
        <UploadIcon /> {isPhotoSubmitted ? "Photo Submetted ! " : "Upload Hive Photo"}
      </label>

 {!isPhotoSubmitted && previewUrl && (
    <div className="mt-4">
      <img 
        src={previewUrl} 
        alt="Preview" 
        className="rounded-lg"
        style={{
          width: '300px',
          height: '200px',
          objectFit: 'cover'
        }}
      />
      <button 
        onClick={handleSubmit}
        className="mt-2 rounded-xl bg-green-500 px-4 py-2 text-white hover:bg-green-600"
      >
        Submit Photo
      </button>
    </div>
  )}
      
    </div>
        <button
          onClick={() => {
            props.AddHive(newHive);
            setNewHive({ hiveName: "", hiveLocation: "", sensorId: "",photoUrl:"" });
            // Reset photo state
              setPreviewUrl("");
              setSelectedFile(null);
              setIsPhotoSubmitted(false);
          }}
          className="flex items-center justify-center rounded-full bg-brand-500 p-3 text-3xl text-white transition duration-200 hover:cursor-pointer hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:text-white dark:hover:bg-brand-300 dark:active:bg-brand-200"
        >
          <AddIcon />
        </button>
      </div>
    </div>
  );
}
export default AddHiveArea;

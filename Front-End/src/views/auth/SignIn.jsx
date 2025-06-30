import InputField from "components/fields/InputField";
import { FcGoogle } from "react-icons/fc";
import Checkbox from "components/checkbox";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Alert from '@mui/material/Alert';
import CheckIcon from '@mui/icons-material/Check';

export default function SignIn() {
  const [full_name, setFull_name] = useState("Beekeeper!")
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isSignUp, setIsSignUp] = useState(false);
  const [isSignUpSecc, setIsSignUpSecc] = useState(false);

  const navigate = useNavigate();

const signUpHandler = async () => {
  // Validate inputs
  if (password !== confirmPassword) {
    setError("Password doesn't match!");
    return;
  }
  if (phoneNumber === '') {
    setError("Phone Number can't be empty!");
    return;
  }
  if (!email || !password) {
    setError("Email and password are required!");
    return;
  }
  setIsLoading(true);
  setError("");

  try {
    const response = await fetch(`${process.env.REACT_APP_API_URL}/api/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password,
        phone_number: phoneNumber,
        full_name: full_name
      }),
    });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || 'Registration failed');
    }

    // If registration is successful
    setIsSignUp(false);
    setIsSignUpSecc(true)
    //navigate('/admin/all-hives'); // navigate to main page 
  } catch (err) {
    setError(err.message || 'An error occurred during registration');
  } finally {
    setIsLoading(false);
  }
};

const signInHandler = async () => {
  setIsLoading(true);
  setError("");

  try {
    const response = await fetch(`${process.env.REACT_APP_API_URL}/api/login`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    // First check if response is OK before parsing JSON
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log('User logged in:', data.user);
    navigate('/admin/all-hives');
  } catch (err) {
    const errorMessage = err.message.includes('JSON') 
      ? 'Invalid server response' 
      : err.message;
    setError(errorMessage);
  } finally {
    setIsLoading(false);
  }
};

const handleGoogleLogin = () => {
  window.location.href = `${process.env.REACT_APP_API_URL}/auth/google`;
}
 


  return (
    <div className="mt-16 mb-16 flex h-full w-full items-center justify-center px-2 md:mx-0 md:px-0 lg:mb-10 lg:items-center lg:justify-start">
      {/* Sign in section */}
      <div className="mt-[10vh] w-full max-w-full flex-col items-center md:pl-4 lg:pl-0 xl:max-w-[420px]">
        <h4 className="mb-2.5 text-4xl font-bold text-navy-700 dark:text-white">
          Sign In
        </h4>
        <p className="mb-9 ml-1 text-base text-gray-600">
          Enter your email and password to sign in!
        </p>
        <div 
          className="mb-6 flex h-[50px] w-full items-center justify-center gap-2 rounded-xl bg-lightPrimary hover:cursor-pointer dark:bg-navy-800"
          onClick={handleGoogleLogin}
        >
          <div className="rounded-full text-xl">
            <FcGoogle />
          </div>
          <h5 className="text-sm font-medium text-navy-700 dark:text-white">
            Sign In with Google
          </h5>
        </div>
        <div className="mb-6 flex items-center  gap-3">
          <div className="h-px w-full bg-gray-200 dark:bg-navy-700" />
          <p className="text-base text-gray-600 dark:text-white"> or </p>
          <div className="h-px w-full bg-gray-200 dark:bg-navy-700" />
        </div>
        
        {/* Error message */}
        {error && (
          <div className="mb-4 text-red-500 text-sm">
            {error}
          </div>
        )}
        {/* Resgister succefull message */}
        {isSignUpSecc ? 
        <Alert icon={<CheckIcon fontSize="inherit" />} severity="success">
  Registration successful! Now you can LogIn.
</Alert>: null}
         {isSignUp ? (
  // full name input
  <InputField
    variant="auth"
    extra="mb-3"
    label="Full Name*"
    placeholder="Flen ben fulen"
    id="fullName"
    type="text"
    value={full_name}
    onChange={(e) => setFull_name(e.target.value)}
  />
) : null}

        {/* Email */}
        <InputField
          variant="auth"
          extra="mb-3"
          label="Email*"
          placeholder="mail@simmmple.com"
          id="email"
          type="text"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        {isSignUp ? (
  // Phone number input
  <InputField
    variant="auth"
    extra="mb-3"
    label="phone*"
    placeholder="123456789"
    id="phone"
    type="text"
    value={phoneNumber}
    onChange={(e) => setPhoneNumber(e.target.value)}
  />
) : null}

        {/* Password */}
        <InputField
          variant="auth"
          extra="mb-3"
          label="Password*"
          placeholder="Min. 8 characters"
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
           {isSignUp ? (
  // confirm password input 
  <InputField
    variant="auth"
          extra="mb-3"
          label="Confirm Password*"
          placeholder="Min. 8 characters"
          id="password"
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
  />
) : null}
        {/* Checkbox */}
        <div className="mb-4 flex items-center justify-between px-2">
          <div className="flex items-center">
            <Checkbox />
            <p className="ml-2 text-sm font-medium text-navy-700 dark:text-white">
              Keep me logged In
            </p>
          </div>
          <a
            className="text-sm font-medium text-brand-500 hover:text-brand-600 dark:text-white"
            href=" "
          >
            Forgot Password?
          </a>
        </div>
        { !isSignUp ? <button 
          onClick={signInHandler} 
          disabled={isLoading}
          className="linear mt-2 w-full rounded-xl bg-brand-500 py-[12px] text-base font-medium text-white transition duration-200 hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:text-white dark:hover:bg-brand-300 dark:active:bg-brand-200"
        >
          {isLoading ? 'Signing In...' : 'Sign In'}
        </button> : <button 
          onClick={signUpHandler} 
          disabled={isLoading}
          className="linear mt-2 w-full rounded-xl bg-brand-500 py-[12px] text-base font-medium text-white transition duration-200 hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:text-white dark:hover:bg-brand-300 dark:active:bg-brand-200"
        >
          {isLoading ? 'Signing Up...' : 'Sign Up'}
        </button>
         }
        {!isSignUp ?
        <div className="mt-4">
          <span className=" text-sm font-medium text-navy-700 dark:text-gray-600">
            Not registered yet?
          </span>
          
          <button onClick={() => setIsSignUp(!isSignUp) }
            className="ml-1 text-sm font-medium text-brand-500 hover:text-brand-600 dark:text-white"
          >
            Create an account
          </button>
        </div> : <button onClick={() => setIsSignUp(!isSignUp) }
            className="ml-1 mt-4 text-sm font-medium text-brand-500 hover:text-brand-600 dark:text-white"
          >
            Sign-In
          </button> }
      </div>
    </div>
  );
}
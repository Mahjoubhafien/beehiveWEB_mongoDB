import React, { useEffect, useState } from "react";
import CardMenu from "components/card/CardMenu";
import Card from "components/card";

const UserSettings = () => {
  const [user, setUser] = useState(null);
  const [formData, setFormData] = useState({
    full_name: "",
    email: "",
    phone_number: "",
    password: "",
  });

  // Fetch user data on mount
  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await fetch(`${process.env.REACT_APP_API_URL}/api/user`, {
          credentials: "include",
        });
        const data = await res.json();
        setUser(data);
        setFormData({
          full_name: data.full_name,
          email: data.email,
          phone_number: data.phone_number,
          password: "",
        });
      } catch (err) {
        console.error("Error fetching user:", err);
      }
    };
    fetchUser();
  }, []);

  const handleChange = (e) =>
    setFormData({ ...formData, [e.target.name]: e.target.value });

const handleSave = async () => {
  // Validate required fields
  if (!formData.full_name.trim()) {
    alert("Full Name cannot be empty");
    return;
  }
  if (!formData.email.trim()) {
    alert("Email cannot be empty");
    return;
  }
  if (!formData.phone_number.trim()) {
    alert("Phone Number cannot be empty");
    return;
  }

  try {
    const res = await fetch(`${process.env.REACT_APP_API_URL}/api/user`, {
      method: "PUT",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(formData),
    });

    if (!res.ok) throw new Error("Failed to update user");

    const updatedUser = await res.json();
    setUser(updatedUser);

    let message = "Profile updated successfully!";
    if (formData.password) message += " Password changed.";

    alert(message);

    setFormData({ ...formData, password: "" }); // reset password field
  } catch (err) {
    console.error(err);
    alert("Error updating profile");
  }
};

  if (!user) return <p>Loading...</p>;

return (
<Card extra={"w-full h-full sm:overflow-auto px-6"}>
            <header className="relative flex items-center justify-between pt-4">
        <div className="flex items-center gap-2 text-xl font-bold text-navy-700 dark:text-white">
          My Profile 
        </div>
        <CardMenu />
      </header>

        <div className="p-5 w-full">

  <div className="mb-2">
    <label className="block text-sm">User ID</label>
    <input
      value={user._id}
      readOnly
      className="border p-2 w-full rounded bg-gray-100 cursor-not-allowed"
    />
  </div>

  <div className="mb-2">
    <label className="block text-sm">Full Name</label>
    <input
      name="full_name"
      value={formData.full_name}
      onChange={handleChange}
      className="border p-2 w-full rounded"
    />
  </div>

  <div className="mb-2">
    <label className="block text-sm">Email</label>
    <input
      name="email"
      type="email"
      value={formData.email}
      onChange={handleChange}
      className="border p-2 w-full rounded"
    />
  </div>

  <div className="mb-2">
    <label className="block text-sm">Phone Number</label>
    <input
      name="phone_number"
      value={formData.phone_number}
      onChange={handleChange}
      className="border p-2 w-full rounded"
    />
  </div>

  <div className="mb-2">
    <label className="block text-sm">Password</label>
    <input
      name="password"
      type="password"
      value={formData.password}
      onChange={handleChange}
      placeholder="New Password"
      className="border p-2 w-full rounded"
    />
  </div>

  <div className="flex justify-center mt-4">
    <button
      onClick={handleSave}
      className="rounded-xl bg-brand-500 px-5 py-3 text-base font-medium text-white transition duration-200 hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:text-white dark:hover:bg-brand-300 dark:active:bg-brand-200"
    >
      Save Changes
    </button>
  </div>
</div>
    </Card>

);
};

export default UserSettings;

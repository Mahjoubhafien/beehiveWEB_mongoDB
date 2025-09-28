import React from "react";

// Admin Imports
import MainDashboard from "views/admin/detailed-dashboard";
import AllHives from "views/admin/all-hives";
import Alerts from "views/admin/alerts";
import AdminSettings from "views/admin/user-settings"
import Home from "views/home/home";
import DataTables from "views/admin/allerts_settings";
import { GoAlert } from "react-icons/go";
import { GiBeehive } from "react-icons/gi";
import { GiHoneycomb } from "react-icons/gi";
import { FaRegAddressCard } from "react-icons/fa";
import { MdOutlineAppSettingsAlt } from "react-icons/md";
import { RiAdminLine } from "react-icons/ri";

// Auth Imports
import SignIn from "views/auth/SignIn";

// Icon Imports
import {
  MdHome,
  MdBarChart,
  MdPerson,
  MdLock,
} from "react-icons/md";

const routes = [
  {
    name: "Hives",
    layout: "/admin",
    path: "all-hives",
    icon: <GiBeehive className="h-6 w-6" />,
    component: <AllHives />,
    secondary: true,
  },
  {
    name: "Dashboard",
    layout: "/admin",
    path: "detailed-dashboard",
    icon: <GiHoneycomb className="h-6 w-6" />,
    component: <MainDashboard />,
  },
  {
    name: "Alerts",
    layout: "/admin",
    path: "Alerts",
    icon: <GoAlert className="h-6 w-6" />,
    component: <Alerts />,
  },
  {
    name: "SMS Settings",
    layout: "/admin",
    icon: <MdOutlineAppSettingsAlt className="h-6 w-6" />,
    path: "SMS_Settings",
    component: <DataTables />,
  },
  {
    name: "User Settings",
    layout: "/admin",
    path: "user-settings",
    icon: <RiAdminLine className="h-6 w-6" />,
    component: <AdminSettings />,
  },
   {
    name: "Sign In",
    layout: "/auth",
    path: "sign-in",
    icon: <MdLock className="h-6 w-6" />,
    component: <SignIn />,
  },
];
export default routes;

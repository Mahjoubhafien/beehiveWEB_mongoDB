import React, { useState } from 'react';
import { GoCpu } from "react-icons/go";
import { FaRegCalendarCheck } from "react-icons/fa";
import { GiDrippingHoney } from "react-icons/gi";
import { GiHoneypot } from "react-icons/gi";
import { GiBeehive } from "react-icons/gi";
import { TbAlertSquareRounded } from "react-icons/tb";
import { motion } from "framer-motion";
import { useInView } from "react-intersection-observer";

const Features = () => {    
      const { ref, inView } = useInView({
    triggerOnce: true, // Only animate once
    threshold: 0.1,     // Trigger when 10% is visible
  });
    
    return (
        <motion.section
      ref={ref}
      initial={{ opacity: 0, y: 50 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.8, ease: "easeOut" }}
    >
<section id="features" className="py-8 bg-white sm:py-10 lg:py-12">  {/* Reduced padding here */}
    <div className="px-4 mx-auto max-w-7xl sm:px-6 lg:px-8">
        <div className="text-center">
            <h2 className="text-4xl font-bold leading-tight text-gray-900 sm:text-5xl sm:leading-tight lg:text-6xl lg:leading-tight font-pj">Improve beehive health, save time and reduce costs with BeeTrack®</h2>
            <p className="mt-4 text-base leading-7 text-gray-600 sm:mt-8 font-pj">
                The ability to balance inspection cadence with BeeTrack's data driven insight<br />
                leads to savings in time, costs and resources while enabling hives to thrive.
            </p>
        </div>

        <div className="grid grid-cols-1 mt-10 text-center sm:mt-16 sm:grid-cols-2 sm:gap-x-12 gap-y-12 md:grid-cols-3 md:gap-0 xl:mt-10">
            {/* All internal content remains unchanged */}
            <div className="md:p-8 lg:p-14">
                <div className="w-16 h-16 mx-auto flex items-center justify-center rounded-full bg-yellow-100">
                    <GoCpu className="text-2xl text-yellow-600" />
                </div>
                <h3 className="mt-12 text-xl font-bold text-gray-900 font-pj">24/7 Insight</h3>
                <p className="mt-5 text-base text-gray-600 font-pj">
                    Confirmation of brood health and homeostasis: 32–36°C temperature and 50–60% humidity is optimal for colony success.
                </p>
            </div>

<div className="md:p-8 lg:p-14 md:border-l md:border-gray-200">
  <div className="w-16 h-16 mx-auto flex items-center justify-center rounded-full bg-yellow-100">
    <FaRegCalendarCheck className="text-2xl text-yellow-600" />
  </div>

  <h3 className="mt-12 text-xl font-bold text-gray-900 font-pj">Inspection Tracking</h3>
  <p className="mt-5 text-base text-gray-600 font-pj">
    Create Inspection notes for each hive: tracking colony health and future actions, all within an easy to use cloud dashboard.
  </p>
</div>

<div className="md:p-8 lg:p-14 md:border-l md:border-gray-200">
  <div className="w-16 h-16 mx-auto flex items-center justify-center rounded-full bg-yellow-100">
    <GiDrippingHoney className="text-2xl text-yellow-600" />
  </div>

  <h3 className="mt-12 text-xl font-bold text-gray-900 font-pj">Queen Status
</h3>
  <p className="mt-5 text-base text-gray-600 font-pj">
A failing queen or weakened colony will lead to volatility within temperature and humidity. Set targeted alerts to stay ahead of negative events.  </p>
</div>


            <div className="md:p-8 lg:p-14 md:border-t">
  <div className="w-16 h-16 mx-auto flex items-center justify-center rounded-full bg-yellow-100">
    <GiHoneypot className="text-2xl text-yellow-600" />
  </div>

  <h3 className="mt-12 text-xl font-bold text-gray-900 font-pj">Honey Output
</h3>
  <p className="mt-5 text-base text-gray-600 font-pj">
Data insights and reduced inspections leads to less colony disturbance and more honey (unnecessary Inspections disrupts a colony for 48 hours)  </p>
</div>


            <div className="md:p-8 lg:p-14 md:border-l md:border-gray-200 md:border-t">
  <div className="w-16 h-16 mx-auto flex items-center justify-center rounded-full bg-yellow-100">
    <GiBeehive className="text-2xl text-yellow-600" />
  </div>

  <h3 className="mt-12 text-xl font-bold text-gray-900 font-pj">Swarm Management
</h3>
  <p className="mt-5 text-base text-gray-600 font-pj">
Set temperature and humidity parameters to alert to swarm events during Spring & Summer (swarm trends: May to July usually between 11am – 4pm) </p>
</div>

            <div className="md:p-8 lg:p-14 md:border-l md:border-gray-200 md:border-t">
  <div className="w-16 h-16 mx-auto flex items-center justify-center rounded-full bg-yellow-100">
    <TbAlertSquareRounded className="text-2xl text-yellow-600" />
  </div>

  <h3 className="mt-12 text-xl font-bold text-gray-900 font-pj">Theft and Storm Alerts
</h3>
  <p className="mt-5 text-base text-gray-600 font-pj">
Targeted and instant movement alerts if a hive is picked up or knocked over in the event of storm, theft or animal disturbance including GPS functionality on HiveBeat Professional. </p>
</div>
        </div>
    </div>
</section>

    </motion.section>
    )
}
export default Features;
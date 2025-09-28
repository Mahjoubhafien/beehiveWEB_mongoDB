import React, { useState } from 'react';
import dash from "assets/img/layout/dashboard.png";
import { motion } from "framer-motion";
import { useInView } from "react-intersection-observer";

const Details_2 = () => {  
    const { ref, inView } = useInView({
        triggerOnce: true, // Only animate once
        threshold: 0.1,     // Trigger when 10% is visible
      });
          
    const [expanded, setExpanded] = useState(false);

    return (
         <motion.section
                  ref={ref}
                  initial={{ opacity: 0, y: 50 }}
                  animate={inView ? { opacity: 1, y: 0 } : {}}
                  transition={{ duration: 0.8, ease: "easeOut" }}
                >
        <div className="overflow-x-hidden bg-gray-50">

            <section className="pt-12 bg-gray-50 sm:pt-16">
                <div className="px-4 mx-auto max-w-7xl sm:px-6 lg:px-8">
                    <div className="max-w-1xl mx-auto text-center">
<div className="flex justify-center">
  <p className="mt-5 text-4xl font-bold text-gray-900 sm:text-5xl lg:text-6xl font-pj text-center">
    <span className="block">Analyse and optimise colony health</span>
    <span className="block">with the BeeTrack® dashboard, anytime, anywhere.</span>
  </p>
</div>
                        <div className="px-8 sm:items-center sm:justify-center sm:px-0 sm:space-x-5 sm:flex mt-9">
                            <a
                                href="admin/detailed-dashboard"
                                title=""
                                style={{ backgroundColor: '#FFC30B', color: '#000' }}
                                className="inline-flex items-center justify-center w-full px-8 py-3 text-lg font-bold text-white transition-all duration-200 bg-gray-900 border-2 border-transparent sm:w-auto rounded-xl font-pj hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-900"
                                role="button"
                            >
                                Dashboard and Alerts
                            </a>

                        
                        </div>

                    </div>
                </div>
                <div className="">
                    <div className="relative">
                        <div className="absolute inset-0 h-2/3 bg-gray-50"></div>
                        <div className="relative mx-auto">
                            <div className="lg:max-w-6xl lg:mx-auto">
                                <img className="w-full max-w-full" src={dash} alt="" />
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </div></motion.section>
    );
}

export default Details_2;
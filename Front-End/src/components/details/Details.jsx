import React from "react";
import { Button } from "@relume_io/relume-ui";
import { RxChevronRight } from "react-icons/rx";
import alert from "assets/img/layout/alert1.png";
import { motion } from "framer-motion";
import { useInView } from "react-intersection-observer";

export const Layout1Defaults = {
  heading: "Receive vital hive health alerts in real-time (SMS & Email)",
  description:
    "BeeTrack’s advanced monitoring & alerting technology allows beekeepers to track colony health via temperature, humidity and movement within their hives, anytime, anywhere. HiveBeat is supporting millions of Bees and thousands of beekeepers around the globe, focusing on sustainable colony management through data driven beekeeping.",
  buttons: [
    {
      title: "Browse Products",
      variant: "link",
      size: "link",
      iconRight: <RxChevronRight />,
    },
  ],
  image: {
    alt: "alert",
  },
};

export const Layout1 = (props) => {
  const { tagline, heading, description, buttons, image } = {
    ...Layout1Defaults,
    ...props,
  };
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
<section id="relume" className="bg-green-50 px-[5%] pb-16 md:pb-24 lg:pb-28 pt-8 md:pt-12 lg:pt-16 ">
      <div className="container">
        <div className="grid grid-cols-1 gap-y-12 md:grid-cols-2 md:items-center md:gap-x-12 lg:gap-x-20">
          <div>

<h2 className="mb-2 text-3xl font-bold leading-tight text-gray-900 sm:text-4xl sm:leading-tight lg:text-5xl lg:leading-tight font-pj">
  {heading}
</h2>            <p className="md:text-md">{description}</p>
            <div className="mt-6 flex flex-wrap items-center gap-4 md:mt-8">
              {buttons.map((button, index) => (
                <Button className=" mt-11 inline-flex items-center px-8 py-4 text-lg font-bold text-white transition-all duration-200 border border-transparent rounded-xl focus:outline-none focus:ring-2 focus:ring-offset-2 font-pj justify-center"
  style={{ backgroundColor: '#FFC30B', color: '#000' }} // optional: use black text
                            role="button" key={index} {...button}>
                  {button.title}
                </Button>
              ))}
            </div>
          </div>
<div className="max-w-[550px] mx-auto"> {/* Adjust 500px to your preferred max width */}
  <img src={alert} className="w-full object-cover" alt={image.alt} />
</div>
        </div>
      </div>
    </section>
    </motion.section>
  );
};

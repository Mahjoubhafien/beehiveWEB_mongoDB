import React from "react";
import Hero from "components/hero/Hero"
import Features from "components/features/Features"
import FooterSection from "components/footersection/FooterSection"
import { Layout1 as Details } from "components/details/Details";
import Details_2 from "components/details2/Details_2"


const HomePage = () => {
  return (
    <div >
  <Hero />
  <Features />
  <Details />
  <Details_2 />
  <FooterSection />
</div>

  );
};

export default HomePage;
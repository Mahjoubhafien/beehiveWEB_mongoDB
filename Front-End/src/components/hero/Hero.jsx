import React, { useState } from 'react';
import logo from "assets/img/layout/beetrack logo.png";
import dashboard from "assets/img/layout/homepagedash.png";
import bk1 from "assets/img/avatars/beekeeper1.png";
import bk2 from "assets/img/avatars/beekeeper2.jpg";
import bk3 from "assets/img/avatars/beekeeper3.jpg";
import CreateIcon from '@mui/icons-material/Create';
const ComponentName = () => {        
    return (
        <div className="relative bg-gray-50">
    <div className="absolute bottom-0 right-0 overflow-hidden lg:inset-y-0">
        <img className="w-auto h-full" src="https://d33wubrfki0l68.cloudfront.net/1e0fc04f38f5896d10ff66824a62e466839567f8/699b5/images/hero/3/background-pattern.png" alt="" />
    </div>

    <header className="relative py-4 md:py-6">
        <div className="px-4 mx-auto max-w-7xl sm:px-6 lg:px-8">
            <div className="flex items-center justify-between">
                <div className="flex-shrink-0">
                    <a href="#" title="" className="flex rounded outline-none focus:ring-1 focus:ring-gray-900 focus:ring-offset-2">
                        <img className="w-auto h-8" src={logo} alt="" />
                    </a>
                </div>

                <div className="flex lg:hidden">
                    <button type="button" className="text-gray-900">
                        <svg className="w-7 h-7" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6h16M4 12h16M4 18h16"></path>
                        </svg>
                    </button>
                </div>

                <div className="hidden lg:flex lg:ml-16 lg:items-center lg:justify-center lg:space-x-10">
                    <div className="flex items-center space-x-12">
                        <a href="#features" title="" className="text-base font-medium text-gray-900 transition-all duration-200 rounded focus:outline-none font-pj hover:text-opacity-50 focus:ring-1 focus:ring-gray-900 focus:ring-offset-2"> Features </a>

                        <a href="#" title="" className="text-base font-medium text-gray-900 transition-all duration-200 rounded focus:outline-none font-pj hover:text-opacity-50 focus:ring-1 focus:ring-gray-900 focus:ring-offset-2"> Product </a>

                        <a href="#" title="" className="text-base font-medium text-gray-900 transition-all duration-200 rounded focus:outline-none font-pj hover:text-opacity-50 focus:ring-1 focus:ring-gray-900 focus:ring-offset-2"> Pricing </a>
                    </div>

                    <div className="w-px h-5 bg-gray-300"></div>

                    <a href="/auth/sign-in" title="" className="text-base font-medium text-gray-900 transition-all duration-200 rounded focus:outline-none font-pj hover:text-opacity-50 focus:ring-1 focus:ring-gray-900 focus:ring-offset-2"> Login </a>

                    <a
                        href="/auth/sign-in"
                        title=""
                        className="
                            px-5
                            py-2
                            text-base
                            font-semibold
                            leading-7
                            text-gray-900
                            transition-all
                            duration-200
                            bg-transparent
                            border border-gray-900
                            rounded-xl
                            font-pj
                            focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-900
                            hover:bg-gray-900 hover:text-white
                            focus:bg-gray-900 focus:text-white
                        "
                        role="button"
                    >
                        Create free account
                    </a>
                </div>
            </div>
        </div>
    </header>

    <section className="relative py-12 sm:py-16 lg:pt-20 lg:pb-36">
        <div className="px-4 mx-auto sm:px-6 lg:px-8 max-w-7xl">
            <div className="grid grid-cols-1 gap-y-8 lg:items-center lg:grid-cols-2 sm:gap-y-20 xl:grid-cols-5">
                <div className="text-center xl:col-span-2 lg:text-left md:px-16 lg:px-0">
                    <div className="max-w-sm mx-auto sm:max-w-md md:max-w-full">
                        <h1 className="text-4xl font-bold leading-tight text-gray-900 sm:text-5xl sm:leading-tight lg:text-6xl lg:leading-tight font-pj">Smart beehive monitoring solution</h1>

                        <div className="mt-8 lg:mt-12 lg:flex lg:items-center">
                            <div className="flex justify-center flex-shrink-0 -space-x-4 overflow-hidden lg:justify-start">
                                <img className="inline-block rounded-full w-14 h-14 ring-2 ring-white" src={bk1} alt="" />
                                <img className="inline-block rounded-full w-14 h-14 ring-2 ring-white" src={bk2} alt="" />
                                <img className="inline-block rounded-full w-14 h-14 ring-2 ring-white" src={bk3} alt="" />
                            </div>

<p className="mt-4 text-lg text-gray-900 lg:mt-0 lg:ml-4 font-pj">
  Trusted by <span className="font-bold">1,000+ professional beekeepers</span>, <span className="font-semibold">BeeTrack®</span> is the next-generation hive management solution.
</p>
                        </div>
                    </div>

                    <div className="mt-8 sm:flex sm:items-center sm:justify-center lg:justify-start sm:space-x-5 lg:mt-12">
                        <a
                            href="/admin/all-hives"
                            title=""
  className="inline-flex items-center px-8 py-4 text-lg font-bold text-white transition-all duration-200 border border-transparent rounded-xl focus:outline-none focus:ring-2 focus:ring-offset-2 font-pj justify-center"
  style={{ backgroundColor: '#FFC30B', color: '#000' }} // optional: use black text
                            role="button"
                        >
                            View Dashboard
                        </a>

                        <a
                            href="#"
                            title=""
                            className="
                                inline-flex
                                items-center
                                px-4
                                py-4
                                mt-4
                                text-lg
                                font-bold
                                transition-all
                                duration-200
                                bg-transparent
                                border border-transparent
                                sm:mt-0
                                font-pj
                                justif-center
                                rounded-xl
                                focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-300
                                hover:bg-gray-200
                                focus:bg-gray-200
                            "
                            role="button"
                        >
                                                      <CreateIcon className="w-5 h-5 mr-2" />
                            Create free account
                        </a>
                    </div>
                </div>

<div className="xl:col-span-3">
  <img
    className="w-full mx-auto scale-110 animate-float"
    src={dashboard}
    alt="Product"
  />
</div>
            </div>
        </div>
    </section>
</div>

    )
}
export default ComponentName;
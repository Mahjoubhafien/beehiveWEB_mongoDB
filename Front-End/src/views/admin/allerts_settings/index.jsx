import SmsAlertsSettings from "./components/SmsSettings";

const Tables = () => {
  return (
    <div>
      <div className="mt-5 grid h-full grid-cols-1 gap-5 md:grid-cols-1">
        <SmsAlertsSettings/>
        
        {/*<CheckTable columnsData={columnsDataCheck} tableData={tableDataCheck} />*/}
      </div>


    </div>
  );
};

export default Tables;

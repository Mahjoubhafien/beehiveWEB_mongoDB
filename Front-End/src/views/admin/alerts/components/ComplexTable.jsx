import React from "react";
import CardMenu from "components/card/CardMenu";
import Card from "components/card";
import { MdCancel, MdCheckCircle, MdOutlineError } from "react-icons/md";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import dayjs from "dayjs";

const columnHelper = createColumnHelper();

export default function ComplexTable(props) {
  const { tableData = [] } = props;
  const [sorting, setSorting] = React.useState([]);
  const [timeFilter, setTimeFilter] = React.useState(24);
  const [currentPage, setCurrentPage] = React.useState(0); // NEW

  const pageSize = 10; // display 6 per page

  // memoize filtered data
  const filteredData = React.useMemo(() => {
    return tableData.filter((item) =>
      dayjs(item.date).isAfter(dayjs().subtract(timeFilter, "hour"))
    );
  }, [tableData, timeFilter]);

  // calculate total pages
  const totalPages = Math.ceil(filteredData.length / pageSize);

  // slice the 6 rows of current page
  const pagedData = React.useMemo(() => {
    const start = currentPage * pageSize;
    return filteredData.slice(start, start + pageSize);
  }, [filteredData, currentPage]);

  const columns = React.useMemo(() => [
    columnHelper.accessor("alert_type", {
      id: "alert_type",
      header: () => (
        <p className="text-sm font-bold text-gray-600 dark:text-white">ALERT TYPE</p>
      ),
      cell: (info) => (
        <p className="text-sm font-bold text-navy-700 dark:text-white">
          {info.getValue()}
        </p>
      ),
    }),
    columnHelper.accessor("status", {
      id: "status",
      header: () => (
        <p className="text-sm font-bold text-gray-600 dark:text-white">STATUS</p>
      ),
      cell: (info) => {
        const status = info.getValue().toLowerCase();
        return (
          <div className="flex items-center">
            {status.includes("high temp") ? (
              <MdOutlineError className="text-amber-500 me-1 dark:text-amber-300" />
            ) : status.includes("normal") ? (
              <MdCheckCircle className="text-green-500 me-1 dark:text-green-300" />
            ) : (
              <MdCancel className="text-red-500 me-1 dark:text-red-300" />
            )}
            <p className="text-sm font-bold text-navy-700 dark:text-white">
              {info.getValue()}
            </p>
          </div>
        );
      },
    }),
    columnHelper.accessor("sensor_id", {
      id: "sensor_id",
      header: () => (
        <p className="text-sm font-bold text-gray-600 dark:text-white">SENSOR ID</p>
      ),
      cell: (info) => (
        <p className="text-sm font-bold text-navy-700 dark:text-white">
          {info.getValue()}
        </p>
      ),
    }),
    columnHelper.accessor("date", {
      id: "date",
      header: () => (
        <p className="text-sm font-bold text-gray-600 dark:text-white">DATE</p>
      ),
      cell: (info) => (
        <p className="text-sm font-bold text-navy-700 dark:text-white">
          {new Date(info.getValue()).toLocaleString()}
        </p>
      ),
    }),
  ], []);

  const table = useReactTable({
    data: pagedData, // use paged data
    columns,
    state: {
      sorting,
    },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });
  //CSV Handler 
const handleDownloadCSV = () => {
  if (!filteredData.length) return;
const headers = ['Alert Type', 'Status', 'Sensor ID', 'Date'];
// use filteredData here to get all filtered rows regardless of pagination
const rows = filteredData.map(row => [
  row.alert_type,
  row.status,
  row.sensor_id,
  new Date(row.date).toLocaleString(),
]);

  // Combine headers and rows
  const csvContent =
    [headers, ...rows]
      .map(e => e.map(cell => `"${cell}"`).join(','))  // quote each cell
      .join('\n');

  // Create a Blob and a download link
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', 'alerts_history.csv');
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};
  return (
    <Card extra={"w-full h-full px-6 pb-6 sm:overflow-x-auto"}>
      <div className="relative flex items-center justify-between pt-4">
        <div className="text-xl font-bold text-navy-700 dark:text-white">
          Alerts History
        </div>
        <CardMenu />
      </div>

      {/* Time Filter Buttons */}
      <div className="mt-4 flex gap-2 items-center">
  {[24, 48, 72].map((hours) => (
    <button
      key={hours}
      onClick={() => {
        setTimeFilter(hours);
        setCurrentPage(0);
      }}
      className={`px-3 py-1 rounded ${
        timeFilter === hours ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700'
      }`}
    >
      Last {hours}h
    </button>
  ))}
  <button
    onClick={handleDownloadCSV}
    className="px-3 py-1 rounded bg-green-600 text-white hover:bg-green-700"
  >
    Download CSV
  </button>
</div>

      {pagedData.length === 0 ? (
        <div className="mt-8 text-center text-gray-500 dark:text-gray-400">
          No alerts found
        </div>
      ) : (
        <>
          <div className="mt-8 overflow-x-scroll xl:overflow-x-hidden">
            <table className="w-full">
              <thead>
                {table.getHeaderGroups().map((headerGroup) => (
                  <tr key={headerGroup.id} className="!border-px !border-gray-400">
                    {headerGroup.headers.map((header) => (
                      <th
                        key={header.id}
                        colSpan={header.colSpan}
                        onClick={header.column.getToggleSortingHandler()}
                        className="cursor-pointer border-b-[1px] border-gray-200 pt-4 pb-2 pr-4 text-start"
                      >
                        <div className="items-center justify-between text-xs text-gray-200">
                          {flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                        </div>
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table
                  .getRowModel()
                  .rows.map((row) => (
                    <tr key={row.id}>
                      {row.getVisibleCells().map((cell) => (
                        <td
                          key={cell.id}
                          className="min-w-[150px] border-white/0 py-3 pr-4"
                        >
                          {flexRender(
                            cell.column.columnDef.cell,
                            cell.getContext()
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          {/* Pagination arrows */}
          <div className="flex justify-center mt-4 gap-4">
            <button
              onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 0))}
              disabled={currentPage === 0}
              className="px-3 py-1 bg-gray-200 rounded disabled:opacity-50"
            >
              ⬅ Prev
            </button>
            <span className="text-sm text-gray-600 dark:text-gray-300">
              Page {currentPage + 1} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((prev) => Math.min(prev + 1, totalPages - 1))}
              disabled={currentPage >= totalPages - 1}
              className="px-3 py-1 bg-gray-200 rounded disabled:opacity-50"
            >
              Next ➡
            </button>
          </div>
        </>
      )}
    </Card>
  );
}

import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { AuditPage } from "./pages/AuditPage";
import { DemoPage } from "./pages/DemoPage";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "approvals", element: <ApprovalsPage /> },
      { path: "audit", element: <AuditPage /> },
      { path: "demo", element: <DemoPage /> },
    ],
  },
]);

export default function App() {
  return <RouterProvider router={router} />;
}

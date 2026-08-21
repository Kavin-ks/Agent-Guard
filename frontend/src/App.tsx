import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { AuditPage } from "./pages/AuditPage";
import { DemoPage } from "./pages/DemoPage";
import { IntegrationPage } from "./pages/IntegrationPage";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "approvals", element: <ApprovalsPage /> },
      { path: "audit", element: <AuditPage /> },
      { path: "integration", element: <IntegrationPage /> },
      { path: "demo", element: <DemoPage /> },
    ],
  },
]);

export default function App() {
  return <RouterProvider router={router} />;
}

// Libraries
import { Toaster } from "react-hot-toast";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
// Layouts
import AppLayout from "./layouts/app/AppLayout";
// Routes
import { authRoutes } from "./routes/auth/auth.route";
import { homeRoutes } from "./routes/home/home.route";

const router = createBrowserRouter([
  {
    path: "/",
    Component: AppLayout,
    children: [authRoutes, homeRoutes],
  },
]);

export default function App() {
  return (
    <>
      <RouterProvider router={router} />
      <Toaster position="bottom-right" />
    </>
  );
}

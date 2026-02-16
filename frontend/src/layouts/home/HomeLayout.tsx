// Libraries
import { Navigate, Outlet, useLocation } from "react-router-dom";
// Stores
import { useTokenStore } from "@/stores/token/token.store";
// Components
import Header from "@/components/header/Header";

export default function HomeLayout() {
  const accessToken = useTokenStore((s) => s.accessToken);
  const location = useLocation();

  if (!accessToken) {
    return <Navigate to="/" replace state={{ from: location.pathname }} />;
  }

  return (
    <div className="h-dvh w-dvw bg-linear-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      <Header />
      <Outlet />
    </div>
  );
}

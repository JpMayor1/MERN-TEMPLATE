// Libraries
import { Navigate, Outlet } from "react-router-dom";
// Stores
import { useTokenStore } from "@/stores/token/token.store";

export default function AuthLayout() {
  const accessToken = useTokenStore((s) => s.accessToken);

  if (accessToken) return <Navigate to="/home" replace />;

  return (
    <div className="h-dvh w-dvw flex flex-col items-center justify-center bg-primary">
      <Outlet />
    </div>
  );
}

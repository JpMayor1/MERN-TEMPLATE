// Libraries
import { useEffect } from "react";
import { Outlet } from "react-router-dom";
// Stores
import { useTokenStore } from "@/stores/token/token.store";
// Components
import SplashScreen from "@/components/general/SplashScreen";

const MIN_SPLASH_MS = 1000;

export default function AppLayout() {
  const loading = useTokenStore((s) => s.loading);
  const accessToken = useTokenStore((s) => s.accessToken);
  const init = useTokenStore((s) => s.init);

  useEffect(() => {
    let cancelled = false;

    const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

    (async () => {
      const start = Date.now();
      await init();

      const elapsed = Date.now() - start;
      const remaining = Math.max(0, MIN_SPLASH_MS - elapsed);
      if (remaining) await sleep(remaining);

      if (cancelled) return;
    })();

    return () => {
      cancelled = true;
    };
  }, [init]);

  if (loading && accessToken === null) return <SplashScreen />;

  return <Outlet />;
}

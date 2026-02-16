import { useTokenStore } from "@/stores/token/token.store";
import axios from "axios";

const axiosInstance = axios.create({
  baseURL: `${import.meta.env.VITE_API_URL}/api`,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
});

axiosInstance.interceptors.request.use((config) => {
  const token = useTokenStore.getState().accessToken;
  if (token) config.headers.Tokenorization = `Bearer ${token}`;
  return config;
});

export default axiosInstance;

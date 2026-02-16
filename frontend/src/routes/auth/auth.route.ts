// Libraries
import type { RouteObject } from "react-router-dom";
// Layouts
import AuthLayout from "@/layouts/auth/AuthLayout";
// Pages
import LoginPage from "@/pages/auth/login/LoginPage";
import RegisterPage from "@/pages/auth/register/RegisterPage";
import LandingPage from "@/pages/general/LandingPage";

export const authRoutes: RouteObject = {
  Component: AuthLayout,
  children: [
    { index: true, Component: LandingPage },
    { path: "auth/login", Component: LoginPage },
    { path: "auth/register", Component: RegisterPage },
  ],
};

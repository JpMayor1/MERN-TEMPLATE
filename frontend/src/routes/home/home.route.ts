// Libraries
import type { RouteObject } from "react-router-dom";
// Layouts
import HomeLayout from "@/layouts/home/HomeLayout";
// Pages
import HomePage from "@/pages/home/HomePage";

export const homeRoutes: RouteObject = {
  path: "home",
  Component: HomeLayout,
  children: [{ index: true, Component: HomePage }],
};

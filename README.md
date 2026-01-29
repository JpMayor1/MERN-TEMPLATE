# MERN Stack Project Setup (TypeScript)

This repository documents the complete setup for a **MERN Stack** application using:

- **MongoDB**
- **Express.js**
- **React (Vite)**
- **Node.js**
- **TypeScript**

The project is split into **frontend** and **backend** folders for clean separation of concerns and scalability.

---

## ✅ Pre-requisites

Make sure the following are installed on your machine:

- **Visual Studio Code**
- **Node.js** (LTS recommended)
- **npm** (comes with Node.js)

Verify installation:

```bash
node -v
npm -v
```

---

## 1. Create Project Folder Structure

Create a project folder with two subfolders:

```text
project-name
│
├── backend
└── frontend
```

Open the project folder in your code editor (VS Code).

---

## 2. Frontend Setup (React + Vite + TypeScript)

Open the `frontend` folder in terminal or command prompt:

```bash
cd frontend
```

### 2.1 Install React using Vite

Official documentation: https://vite.dev/guide

Command:

```bash
npm create vite@latest . -- --template react-ts
```

You will be asked questions:

- **Use rolldown-vite (Experimental)?**  
  Choose **No** and hit Enter

- **Install with npm and start now?**  
  Choose **Yes** and hit Enter

---

### 2.2 Remove Unnecessary Files and Content

- Delete `App.css`
- Clear all the content of `src/index.css` (but don’t delete the file)
- Update `src/App.tsx`:

```tsx
function App() {
  return (
    <div>
      <h1>Remove Unnecessary Files & Content</h1>
    </div>
  );
}

export default App;
```

---

### 2.3 Install Default Frontend Dependencies

Stop the frontend if running:

- Open the terminal where the frontend was running
- Press `Ctrl + C`
- Type `y` and hit Enter (if prompted)

#### Step 1: Install React Router DOM

Official documentation: https://reactrouter.com

Command:

```bash
npm install react-router-dom
```

Configure the entry point by updating `src/App.tsx`:

```tsx
import { createBrowserRouter, RouterProvider } from "react-router";

function Home() {
  return (
    <div>
      <h1>React Router DOM Setup</h1>
    </div>
  );
}

function App() {
  const router = createBrowserRouter([
    {
      path: "/",
      Component: Home,
    },
  ]);

  return (
    <div>
      <RouterProvider router={router} />
    </div>
  );
}

export default App;
```

---

#### Step 2: Install Tailwind CSS (Updated – Vite Plugin)

Official documentation: https://tailwindcss.com/docs

Command:

```bash
npm install tailwindcss @tailwindcss/vite
```

Configure Vite by updating `vite.config.ts`:

```ts
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
});
```

Update `src/index.css`:

```css
@import "tailwindcss";
```

---

#### Step 3: Install Zustand

Official documentation: https://zustand.docs.pmnd.rs

```bash
npm install zustand
```

---

#### Step 4: Install React Icons

Official documentation: https://react-icons.github.io/react-icons

```bash
npm install react-icons
```

---

#### Step 5: Install React Hot Toast

Official documentation: https://react-hot-toast.com/docs

```bash
npm install react-hot-toast
```

---

#### Step 6: Make Imports Using Alias (`@`)

Configure a path alias so you can import from `src` using `@/...`.

Update `vite.config.ts`:

```ts
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
```

Update `tsconfig.app.json`:

```json
{
  "compilerOptions": {
    "tsBuildInfoFile": "./node_modules/.tmp/tsconfig.app.tsbuildinfo",
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "types": ["vite/client"],
    "skipLibCheck": true,

    /* Bundler mode */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "verbatimModuleSyntax": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",

    /* Linting */
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "erasableSyntaxOnly": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src"]
}
```

Example usage:

```ts
import Button from "@/components/Button";
```

---

#### Step 7: Run the Frontend

```bash
npm run dev
```

---

### 2.4 Frontend Folder Structure

Add the folders if needed. This will be the standard folder structure:

```text
frontend
│
├── node_modules
├── public
├── src
│   ├── api
│   ├── assets
│   ├── components
│   ├── layouts
│   ├── pages
│   ├── stores
│   ├── types
│   └── utils
│
├── .gitignore
├── eslint.config.js
├── index.html
├── package-lock.json
├── package.json
├── README.md
├── tsconfig.app.json
├── tsconfig.json
├── tsconfig.node.json
└── vite.config.ts
```

---

## 3. Backend Setup (Node.js + Express + TypeScript + MongoDB)

Open the `backend` folder in terminal or command prompt:

```bash
cd backend
```

### 3.1 Initialize Backend Project

```bash
npm init -y
```

---

### 3.2 Install Backend Dependencies

#### Core Packages

```bash
npm install express mongoose cors dotenv cookie-parser bcryptjs jsonwebtoken morgan helmet express-rate-limit express-mongo-sanitize
```

#### Type Definitions and Dev Tools

```bash
npm install -D typescript tsx @types/node @types/express @types/cors @types/cookie-parser @types/bcryptjs @types/jsonwebtoken @types/morgan @types/express-rate-limit @types/express-mongo-sanitize
```

---

### 3.3 Initialize TypeScript

```bash
npx tsc --init
```

Update `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "moduleResolution": "node",
    "baseUrl": ".",
    "paths": { "@/*": ["src/*"] },
    "sourceMap": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}
```

---

### 3.4 Add Folders and Files

#### Step 1: Create `.env` file

```env
PORT=5000
NODE_ENV=development
MONGO_DB_URI=mongodb://127.0.0.1:27017/project_name
JWT_SECRET=your_secure_secret_key
CORS_ORIGINS=http://localhost:5173
GLOBAL_RATE_LIMIT_MINUTES=limit_number
GLOBAL_RATE_LIMIT_MAX=limit_number
AUTH_RATE_LIMIT_MINUTES=limit_number
AUTH_RATE_LIMIT_MAX=limit_number
```

#### Step 2: Create `.gitignore`

```text
node_modules
build
bundle
*.env
*.production
```

#### Step 3: Create `src/db/db.connect.ts`

```ts
import mongoose from "mongoose";

export default async function initDB() {
  try {
    mongoose.set("strictQuery", true);
    mongoose.set("strict", true);

    await mongoose.connect(process.env.MONGO_DB_URI as string);
    console.log("Connected to MongoDB");
  } catch (err) {
    console.error("MongoDB connection error:", err);
    return;
  }
}
```

#### Step 4: Create `src/utils/error/app-error.util.ts`

```ts
export class AppError extends Error {
  statusCode: number;
  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}
```

#### Step 5: Create `src/middlewares/globar-error-handler.middleware.ts`

```ts
import { AppError } from "@/utils/error/app-error.util";
import { NextFunction, Request, Response } from "express";

export const globalErrorHandler = (
  err: any,
  req: Request,
  res: Response,
  _next: NextFunction,
) => {
  const isDev = process.env.NODE_ENV === "development";
  let statusCode = err.statusCode || 500;
  let message = err.message || "Something went wrong.";

  // Handle AppError
  if (err instanceof AppError) {
    statusCode = err.statusCode;
    message = err.message;
  }

  console.error(`[ERROR]: ${err.message}\n${err.stack}`);

  res.status(statusCode).json({
    success: false,
    message,
    ...(isDev && { stack: err.stack }),
  });
};
```

#### Step 6: Create `src/middlewares/limiter.middleware.ts`

```ts
import { rateLimit } from "express-rate-limit";

const toMs = (minutes: number) => minutes * 60 * 1000;

// Global limiter
export const globalRateLimiter = rateLimit({
  windowMs: toMs(Number(process.env.GLOBAL_RATE_LIMIT_MINUTES) || 15),
  max: Number(process.env.GLOBAL_RATE_LIMIT_MAX) || 100,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
```

#### Step 7: Create `src/index.ts`

```ts
import dotenv from "dotenv";
dotenv.config();

import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import mongoSanitize from "express-mongo-sanitize";
import helmet from "helmet";
import http from "http";
import morgan from "morgan";

import initDB from "@/db/db.connect.js";
import { globalErrorHandler } from "./middlewares/global-error-handler.middleware";
import { globalRateLimiter } from "./middlewares/limiter.middleware";

const bootstrap = async () => {
  const app = express();
  app.set("trust proxy", 1);

  const PORT = process.env.PORT || 5000;
  const allowedOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(",")
    : [];

  // CORS
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        }

        // Reject everything else
        callback(new Error("CORS not allowed"), false);
      },
      credentials: true,
    }),
  );

  // Security headers
  app.use(helmet());

  // Rate limiting
  app.use(globalRateLimiter);

  // Logger
  app.use(morgan("dev"));

  // JSON parser
  app.use(express.json());

  // Prevent NoSQL Injection
  app.use(mongoSanitize());

  // Cookie parser
  app.use(cookieParser());

  // Root
  app.get("/api/test", (req, res) => {
    res.status(200).send("Api is running");
  });

  // Routes
  // app.use("api", route);

  // Error handler
  app.use(globalErrorHandler);

  const server = http.createServer(app);
  server.setTimeout(300000);

  server.listen(PORT, () => {
    initDB();
    console.log(`Server Running on port ${PORT}`);
  });
};

bootstrap().catch((e) => {
  console.error("Fatal boot error:", e);
  process.exit(1);
});
```

#### Step 8: Update `package.json` scripts

```json
"scripts": {
  "dev": "tsx watch --env-file .env src/index.ts",
  "typecheck": "tsc --noEmit"
}
```

#### Step 9: Run the server

```bash
npm run dev
```

---

### 3.5 Backend Folder Structure

```text
backend
│
├── node_modules
├── src
│   ├── controllers
│   ├── db
│   ├── middlewares
│   ├── models
│   ├── routes
│   ├── services
│   ├── types
│   ├── utils
│   └── index.ts
│
├── .env
├── .gitignore
├── package-lock.json
├── package.json
└── tsconfig.json
```

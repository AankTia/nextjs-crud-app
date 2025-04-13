# Building a Comprehensive Next.js CRUD Application with SQLite Authentication

This guide will walk you through creating a full-stack CRUD (Create, Read, Update, Delete) application with Next.js and SQLite, including user authentication.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Key Implementation Details](#key-implementation-details)
3. [Project Setup](#project-setup)
4. [Database Configuration](#database-configuration)
5. [Authentication](#authentication)
6. [API Routes](#api-routes)
7. [CRUD Operations](#crud-operations)
8. [Frontend Development](#frontend-development)
9. [Deployment Considerations](#deployment-considerations)
10. [Conclusion](#conclusion)
11. [Next Steps](#next-steps)

---

## Project Overview

We've created a full-stack application with:

1. **User Authentication**

   - Registration and login functionality
   - Protected routes with middleware
   - Session management with Next-Auth
   - Secure password handling with bcrypt

2. **Database Management**

   - SQLite integration using better-sqlite3
   - Prepared statements for security
   - Schema for users and items
   - Database initialization and migration strategy

3. **CRUD Operations**

   - Create, read, update, and delete items
   - User-specific data isolation
   - Form handling with validation
   - Proper error handling

4. Frontend Interface

   - Responsive design with Tailwind CSS
   - Dashboard for item management
   - Form components for adding/editing items
   - Authentication pages

---

## Key Implementation Details

### Authentication Flow

The authentication is handled through NextAuth.js which provides:

- JWT-based sessions
- Credentials provider for email/password login
- Protected route middleware
- Session context for frontend components

### Database Security

We're using:

- Prepared statements to prevent SQL injection
- Password hashing with bcrypt
- User-scoped queries (each user can only access their own data)
- Transaction support for data integrity

### React Components

We've created several components:

- Auth context provider for state management
- Login and registration forms
- Dashboard with item listing
- Form components for creating and editing items

---

## Project Setup

First, let's create a new Next.js application with TypeScript:

```bash
npx create-next-app@latest nextjs-crud-app
cd nextjs-crud-app
```

During the setup, select the following options:

- TypeScript: Yes
- ESLint: Yes
- Tailwind CSS: Yes
- App Router: Yes
- Import alias: Yes (default is @/\*)

Next, install the required dependencies:

```bash
npm install better-sqlite3 bcryptjs jsonwebtoken next-auth
npm install @types/better-sqlite3 @types/bcryptjs @types/jsonwebtoken --save-dev
```

---

## Database Configuration

Create a `db` directory in the project root to manage your SQLite database:

```bash
mkdir -p db
```

Create a database utility file:

```typescript
// db/db.ts
import sqlite3 from "better-sqlite3";
import path from "path";
import fs from "fs";

// Make sure the db directory exists
const dbDir = path.resolve("./db");
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, "database.sqlite");
const db = sqlite3(dbPath);

// Enable foreign keys
db.pragma("foreign_keys = ON");

// Initialize database with tables
export function initDatabase() {
  // Create users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create items table (example for CRUD operations)
  db.exec(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      user_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  console.log("Database initialized successfully");
}

// Prepare statements for reuse (better performance)
const preparedStatements = {
  // User-related queries
  getUserByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
  getUserById: db.prepare(
    "SELECT id, username, email, created_at FROM users WHERE id = ?"
  ),
  createUser: db.prepare(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
  ),

  // Item-related queries
  getItems: db.prepare("SELECT * FROM items WHERE user_id = ?"),
  getItemById: db.prepare("SELECT * FROM items WHERE id = ? AND user_id = ?"),
  createItem: db.prepare(
    "INSERT INTO items (title, description, user_id) VALUES (?, ?, ?)"
  ),
  updateItem: db.prepare(
    "UPDATE items SET title = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
  ),
  deleteItem: db.prepare("DELETE FROM items WHERE id = ? AND user_id = ?"),
};

export { db, preparedStatements };
```

Initialize the database in a setup script:

```typescript
// scripts/init-db.ts
import { initDatabase } from "../db/db";

// Initialize the database
initDatabase();

console.log("Database setup completed.");
```

Add a script to your package.json:

```json
"scripts": {
  "dev": "next dev",
  "build": "next build",
  "start": "next start",
  "lint": "next lint",
  "init-db": "ts-node --transpile-only scripts/init-db.ts"
}
```

---

## Authentication

First, create authentication-related types:

```typescript
// types/auth.ts
export interface User {
  id: number;
  username: string;
  email: string;
  created_at: string;
}

export interface Credentials {
  email: string;
  password: string;
}

export interface RegistrationData extends Credentials {
  username: string;
}
```

Set up NextAuth.js for authentication:

```typescript
// app/api/auth/[...nextauth]/route.ts
import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import { preparedStatements } from "@/db/db";

const handler = NextAuth({
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Email and password are required");
        }

        // Fetch user from the database
        const user = preparedStatements.getUserByEmail.get(credentials.email);

        if (!user) {
          throw new Error("No user found with this email");
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(
          credentials.password,
          user.password
        );

        if (!isPasswordValid) {
          throw new Error("Invalid password");
        }

        // Return user without password
        return {
          id: user.id.toString(),
          name: user.username,
          email: user.email,
        };
      },
    }),
  ],
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
      }
      return token;
    },
    async session({ session, token }) {
      if (session?.user) {
        session.user.id = token.id as string;
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
});

export { handler as GET, handler as POST };
```

---

## API Routes

Create API routes for user registration:

```typescript
// app/api/register/route.ts
import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { preparedStatements, db } from "@/db/db";

export async function POST(request: NextRequest) {
  try {
    const { username, email, password } = await request.json();

    // Validate inputs
    if (!username || !email || !password) {
      return NextResponse.json(
        { error: "Missing required fields" },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existingUser = preparedStatements.getUserByEmail.get(email);
    if (existingUser) {
      return NextResponse.json(
        { error: "User already exists with this email" },
        { status: 409 }
      );
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const result = preparedStatements.createUser.run(
      username,
      email,
      hashedPassword
    );

    return NextResponse.json(
      {
        message: "User created successfully",
        userId: result.lastInsertRowid,
      },
      { status: 201 }
    );
  } catch (error: any) {
    console.error("Registration error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to register user" },
      { status: 500 }
    );
  }
}
```

---

## CRUD Operations

Now, let's create API routes for CRUD operations:

```typescript
// app/api/items/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { preparedStatements } from "@/db/db";

// Get all items for current user
export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userId = parseInt(session.user.id);
    const items = preparedStatements.getItems.all(userId);

    return NextResponse.json({ items }, { status: 200 });
  } catch (error: any) {
    console.error("Get items error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to fetch items" },
      { status: 500 }
    );
  }
}

// Create a new item
export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { title, description } = await request.json();

    if (!title) {
      return NextResponse.json({ error: "Title is required" }, { status: 400 });
    }

    const userId = parseInt(session.user.id);
    const result = preparedStatements.createItem.run(
      title,
      description || "",
      userId
    );

    return NextResponse.json(
      {
        message: "Item created successfully",
        itemId: result.lastInsertRowid,
      },
      { status: 201 }
    );
  } catch (error: any) {
    console.error("Create item error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to create item" },
      { status: 500 }
    );
  }
}
```

Create routes for individual item operations:

```typescript
// app/api/items/[id]/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { preparedStatements } from "@/db/db";

// Get a specific item
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const itemId = parseInt(params.id);
    const userId = parseInt(session.user.id);

    const item = preparedStatements.getItemById.get(itemId, userId);

    if (!item) {
      return NextResponse.json({ error: "Item not found" }, { status: 404 });
    }

    return NextResponse.json({ item }, { status: 200 });
  } catch (error: any) {
    console.error("Get item error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to fetch item" },
      { status: 500 }
    );
  }
}

// Update an item
export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { title, description } = await request.json();

    if (!title) {
      return NextResponse.json({ error: "Title is required" }, { status: 400 });
    }

    const itemId = parseInt(params.id);
    const userId = parseInt(session.user.id);

    // Check if item exists and belongs to user
    const item = preparedStatements.getItemById.get(itemId, userId);

    if (!item) {
      return NextResponse.json({ error: "Item not found" }, { status: 404 });
    }

    // Update the item
    preparedStatements.updateItem.run(title, description || "", itemId, userId);

    return NextResponse.json(
      { message: "Item updated successfully" },
      { status: 200 }
    );
  } catch (error: any) {
    console.error("Update item error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to update item" },
      { status: 500 }
    );
  }
}

// Delete an item
export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const itemId = parseInt(params.id);
    const userId = parseInt(session.user.id);

    // Check if item exists and belongs to user
    const item = preparedStatements.getItemById.get(itemId, userId);

    if (!item) {
      return NextResponse.json({ error: "Item not found" }, { status: 404 });
    }

    // Delete the item
    preparedStatements.deleteItem.run(itemId, userId);

    return NextResponse.json(
      { message: "Item deleted successfully" },
      { status: 200 }
    );
  } catch (error: any) {
    console.error("Delete item error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to delete item" },
      { status: 500 }
    );
  }
}
```

---

## Frontend Development

Create authentication context to manage auth state across the app:

```typescript
// contexts/AuthContext.tsx
"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  ReactNode,
} from "react";
import { useSession, signIn, signOut } from "next-auth/react";
import { useRouter } from "next/navigation";

interface AuthContextType {
  user: any;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (
    username: string,
    email: string,
    password: string
  ) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { data: session, status } = useSession();
  const [user, setUser] = useState<any>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const router = useRouter();

  useEffect(() => {
    if (status === "loading") {
      setIsLoading(true);
    } else {
      setUser(session?.user || null);
      setIsLoading(false);
    }
  }, [session, status]);

  const login = async (email: string, password: string) => {
    try {
      setIsLoading(true);
      const result = await signIn("credentials", {
        redirect: false,
        email,
        password,
      });

      if (result?.error) {
        throw new Error(result.error);
      }

      router.push("/dashboard");
    } catch (error) {
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (
    username: string,
    email: string,
    password: string
  ) => {
    try {
      setIsLoading(true);
      const response = await fetch("/api/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Registration failed");
      }

      // Login after successful registration
      await login(email, password);
    } catch (error) {
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      setIsLoading(true);
      await signOut({ redirect: false });
      router.push("/login");
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
```

Now, let's create a provider wrapper for the application:

```typescript
// app/providers.tsx
"use client";

import { SessionProvider } from "next-auth/react";
import { AuthProvider } from "@/contexts/AuthContext";
import { ReactNode } from "react";

export function Providers({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <AuthProvider>{children}</AuthProvider>
    </SessionProvider>
  );
}
```

Update your app layout:

```typescript
// app/layout.tsx
import "./globals.css";
import { Providers } from "./providers";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Next.js CRUD App",
  description: "A comprehensive CRUD application with authentication",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

Create a login page:

```typescript
// app/login/page.tsx
"use client";

import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import Link from "next/link";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const { login, isLoading } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      await login(email, password);
    } catch (err: any) {
      setError(err.message || "Login failed");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-10 bg-white rounded-xl shadow-md">
        <div className="text-center">
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
        </div>

        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            {error}
          </div>
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="email" className="sr-only">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={isLoading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
              {isLoading ? "Signing in..." : "Sign in"}
            </button>
          </div>

          <div className="text-sm text-center">
            <Link
              href="/register"
              className="font-medium text-indigo-600 hover:text-indigo-500">
              Don't have an account? Register
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
```

Create a registration page:

```typescript
// app/register/page.tsx
"use client";

import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import Link from "next/link";

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const { register, isLoading } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      await register(username, email, password);
    } catch (err: any) {
      setError(err.message || "Registration failed");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-10 bg-white rounded-xl shadow-md">
        <div className="text-center">
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
            Create an account
          </h2>
        </div>

        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
            {error}
          </div>
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="username" className="sr-only">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="email" className="sr-only">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={6}
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={isLoading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
              {isLoading ? "Creating account..." : "Register"}
            </button>
          </div>

          <div className="text-sm text-center">
            <Link
              href="/login"
              className="font-medium text-indigo-600 hover:text-indigo-500">
              Already have an account? Sign in
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
```

Create a dashboard page to list and manage items:

```typescript
// app/dashboard/page.tsx
"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { useRouter } from "next/navigation";
import Link from "next/link";

interface Item {
  id: number;
  title: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export default function Dashboard() {
  const { user, isLoading: authLoading, logout } = useAuth();
  const [items, setItems] = useState<Item[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const router = useRouter();

  useEffect(() => {
    // Redirect if not authenticated
    if (!authLoading && !user) {
      router.push("/login");
      return;
    }

    // Fetch items
    if (user) {
      fetchItems();
    }
  }, [user, authLoading, router]);

  const fetchItems = async () => {
    try {
      setIsLoading(true);
      const response = await fetch("/api/items");

      if (!response.ok) {
        throw new Error("Failed to fetch items");
      }

      const data = await response.json();
      setItems(data.items || []);
    } catch (err: any) {
      setError(err.message || "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Are you sure you want to delete this item?")) {
      return;
    }

    try {
      const response = await fetch(`/api/items/${id}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        throw new Error("Failed to delete item");
      }

      // Remove the deleted item from the state
      setItems(items.filter((item) => item.id !== id));
    } catch (err: any) {
      setError(err.message || "An error occurred");
    }
  };

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-lg">Loading...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <h1 className="text-xl font-bold">CRUD App</h1>
              </div>
            </div>
            <div className="flex items-center">
              <span className="mr-4">Hello, {user?.name}</span>
              <button
                onClick={logout}
                className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded">
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-semibold">Your Items</h2>
            <Link
              href="/dashboard/items/new"
              className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-2 px-4 rounded">
              Add New Item
            </Link>
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
              {error}
            </div>
          )}

          {isLoading ? (
            <p>Loading items...</p>
          ) : items.length === 0 ? (
            <div className="bg-white shadow rounded-lg p-6 text-center">
              <p className="text-gray-500">
                You don't have any items yet. Create your first one!
              </p>
            </div>
          ) : (
            <div className="bg-white shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200">
                {items.map((item) => (
                  <li key={item.id}>
                    <div className="px-6 py-4 flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-medium text-gray-900">
                          {item.title}
                        </h3>
                        <p className="mt-1 text-sm text-gray-500">
                          {item.description || "No description"}
                        </p>
                        <p className="mt-1 text-xs text-gray-400">
                          Created: {new Date(item.created_at).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex space-x-2">
                        <Link
                          href={`/dashboard/items/${item.id}/edit`}
                          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 px-3 rounded text-sm">
                          Edit
                        </Link>
                        <button
                          onClick={() => handleDelete(item.id)}
                          className="bg-red-500 hover:bg-red-700 text-white font-bold py-1 px-3 rounded text-sm">
                          Delete
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
```

Let's create pages for adding and editing items:

```typescript
// app/dashboard/items/new/page.tsx
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function NewItemPage() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      setIsLoading(true);

      const response = await fetch("/api/items", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ title, description }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to create item");
      }

      router.push("/dashboard");
    } catch (err: any) {
      setError(err.message || "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="mb-6">
            <h2 className="text-2xl font-semibold">Create New Item</h2>
            <Link
              href="/dashboard"
              className="text-indigo-600 hover:text-indigo-900">
              &larr; Back to Dashboard
            </Link>
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
              {error}
            </div>
          )}

          <div className="bg-white shadow sm:rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <form onSubmit={handleSubmit}>
                <div className="mb-4">
                  <label
                    htmlFor="title"
                    className="block text-sm font-medium text-gray-700">
                    Title
                  </label>
                  <input
                    type="text"
                    id="title"
                    className="mt-1 focus:ring-indigo-500 focus:border-indigo-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md p-2 border"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                <div className="mb-4">
                  <label
                    htmlFor="description"
                    className="block text-sm font-medium text-gray-700">
                    Description
                  </label>
                  <textarea
                    id="description"
                    rows={4}
                    className="mt-1 focus:ring-indigo-500 focus:border-indigo-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md p-2 border"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>

                <div className="flex justify-end">
                  <button
                    type="button"
                    className="mr-2 bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded"
                    onClick={() => router.push("/dashboard")}>
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-2 px-4 rounded"
                    disabled={isLoading}>
                    {isLoading ? "Creating..." : "Create Item"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// app/dashboard/items/[id]/edit/page.tsx
("use client");

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function EditItemPage({ params }: { params: { id: string } }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();
  const itemId = params.id;

  useEffect(() => {
    const fetchItem = async () => {
      try {
        const response = await fetch(`/api/items/${itemId}`);

        if (!response.ok) {
          throw new Error("Failed to fetch item");
        }

        const data = await response.json();

        setTitle(data.item.title);
        setDescription(data.item.description || "");
      } catch (err: any) {
        setError(err.message || "An error occurred");
      } finally {
        setIsLoading(false);
      }
    };

    fetchItem();
  }, [itemId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      setIsSaving(true);

      const response = await fetch(`/api/items/${itemId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ title, description }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to update item");
      }

      router.push("/dashboard");
    } catch (err: any) {
      setError(err.message || "An error occurred");
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-lg">Loading...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="mb-6">
            <h2 className="text-2xl font-semibold">Edit Item</h2>
            <Link
              href="/dashboard"
              className="text-indigo-600 hover:text-indigo-900">
              &larr; Back to Dashboard
            </Link>
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
              {error}
            </div>
          )}

          <div className="bg-white shadow sm:rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <form onSubmit={handleSubmit}>
                <div className="mb-4">
                  <label
                    htmlFor="title"
                    className="block text-sm font-medium text-gray-700">
                    Title
                  </label>
                  <input
                    type="text"
                    id="title"
                    className="mt-1 focus:ring-indigo-500 focus:border-indigo-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md p-2 border"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                <div className="mb-4">
                  <label
                    htmlFor="description"
                    className="block text-sm font-medium text-gray-700">
                    Description
                  </label>
                  <textarea
                    id="description"
                    rows={4}
                    className="mt-1 focus:ring-indigo-500 focus:border-indigo-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md p-2 border"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>

                <div className="flex justify-end">
                  <button
                    type="button"
                    className="mr-2 bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded"
                    onClick={() => router.push("/dashboard")}>
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                    disabled={isSaving}>
                    {isSaving ? "Saving..." : "Save Changes"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
```

Let's create a protected route middleware:

```typescript
// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

export async function middleware(request: NextRequest) {
  const session = await getToken({ req: request });
  const pathname = request.nextUrl.pathname;

  // Protect routes that require authentication
  if (pathname.startsWith("/dashboard") && !session) {
    const url = new URL("/login", request.url);
    url.searchParams.set("callbackUrl", encodeURI(pathname));
    return NextResponse.redirect(url);
  }

  // Redirect authenticated users trying to access login/register to dashboard
  if ((pathname === "/login" || pathname === "/register") && session) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

// Only run middleware on these paths
export const config = {
  matcher: ["/dashboard/:path*", "/login", "/register"],
};
```

Create a home page with redirection:

```typescript
// app/page.tsx
"use client";

import { useEffect } from "react";
import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function Home() {
  const { data: session, status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === "authenticated") {
      router.push("/dashboard");
    }
  }, [status, router]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50">
      <main className="flex flex-col items-center justify-center w-full flex-1 px-20 text-center">
        <h1 className="text-6xl font-bold">
          Welcome to <span className="text-indigo-600">CRUD App</span>
        </h1>

        <p className="mt-3 text-2xl">
          A comprehensive Next.js application with authentication and CRUD
          operations
        </p>

        <div className="mt-6 flex max-w-4xl flex-wrap items-center justify-around sm:w-full">
          {status === "loading" ? (
            <p>Loading...</p>
          ) : !session ? (
            <>
              <Link
                href="/login"
                className="p-6 mt-6 text-left border w-96 rounded-xl hover:text-indigo-600 focus:text-indigo-600">
                <h3 className="text-2xl font-bold">Sign In &rarr;</h3>
                <p className="mt-4 text-xl">
                  Log in to your account to manage your items
                </p>
              </Link>

              <Link
                href="/register"
                className="p-6 mt-6 text-left border w-96 rounded-xl hover:text-indigo-600 focus:text-indigo-600">
                <h3 className="text-2xl font-bold">Register &rarr;</h3>
                <p className="mt-4 text-xl">
                  Create a new account to get started
                </p>
              </Link>
            </>
          ) : (
            <Link
              href="/dashboard"
              className="p-6 mt-6 text-left border w-96 rounded-xl hover:text-indigo-600 focus:text-indigo-600">
              <h3 className="text-2xl font-bold">Dashboard &rarr;</h3>
              <p className="mt-4 text-xl">
                Go to your dashboard to manage your items
              </p>
            </Link>
          )}
        </div>
      </main>

      <footer className="flex items-center justify-center w-full h-24 border-t">
        <p>Built with Next.js, SQLite, and NextAuth.js</p>
      </footer>
    </div>
  );
}
```

---

## Deployment Considerations

For deployment, there are a few considerations specific to SQLite in a production environment:

1. **Database Location**: Make sure your database file is stored in a persistent directory that won't be wiped between deployments.

```typescript
// Update your db.ts file to use environment variables for the DB path
const dbPath = process.env.DATABASE_PATH || path.join(dbDir, "database.sqlite");
```

2. **Database Migrations**: Create a migrations system for safely upgrading your database schema:

```typescript
// db/migrations.ts
import { db } from "./db";

interface Migration {
  version: number;
  up: () => void;
}

const migrations: Migration[] = [
  {
    version: 1,
    up: () => {
      // Initial schema, already created in initDatabase()
    },
  },
  {
    version: 2,
    up: () => {
      // Example migration: add a new column
      db.exec('ALTER TABLE items ADD COLUMN priority TEXT DEFAULT "medium"');
    },
  },
  // Add more migrations as your app evolves
];

export function runMigrations() {
  // Create migrations table if it doesn't exist
  db.exec(`
    CREATE TABLE IF NOT EXISTS migrations (
      version INTEGER PRIMARY KEY,
      applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Get current version
  const currentVersionRow = db
    .prepare("SELECT MAX(version) as version FROM migrations")
    .get();
  const currentVersion = currentVersionRow ? currentVersionRow.version || 0 : 0;

  // Apply needed migrations in a transaction
  const migrationsToApply = migrations.filter(
    (m) => m.version > currentVersion
  );

  if (migrationsToApply.length > 0) {
    console.log(`Applying ${migrationsToApply.length} migrations...`);

    db.transaction(() => {
      for (const migration of migrationsToApply) {
        console.log(`Migrating to version ${migration.version}...`);
        migration.up();
        db.prepare("INSERT INTO migrations (version) VALUES (?)").run(
          migration.version
        );
      }
    })();

    console.log("Database migrations completed successfully.");
  } else {
    console.log("Database is up to date.");
  }
}
```

3. **Backup Strategy**: Implement regular backups of your SQLite database file:

```typescript
// scripts/backup-db.ts
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

// Configure these paths
const dbPath =
  process.env.DATABASE_PATH ||
  path.join(process.cwd(), "db", "database.sqlite");
const backupDir = path.join(process.cwd(), "db-backups");

// Ensure backup directory exists
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
}

// Create timestamped backup
const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
const backupPath = path.join(backupDir, `database-${timestamp}.sqlite`);

// Copy the database file (this works when the database is not in use)
// For production, consider using the SQLite .backup command through better-sqlite3
try {
  fs.copyFileSync(dbPath, backupPath);
  console.log(`Backup created at: ${backupPath}`);
} catch (err) {
  console.error("Backup failed:", err);
  process.exit(1);
}
```

4. **Environment Variables**: Set up environment variables for configuration:

```typescript
// .env.local example (do not commit to version control)
DATABASE_PATH=./db/production.sqlite
NEXTAUTH_SECRET=your-nextauth-secret-key
NEXTAUTH_URL=https://your-production-domain.com
```

---

## Additional Features to Consider

To enhance your application, consider implementing these features:

1. **Password Reset Flow**:

   - Create password reset request endpoint
   - Generate and store reset tokens
   - Email integration for sending reset links
   - Reset password form and API endpoint

2. **User Profile Management**:

   - Profile editing functionality
   - Avatar/image upload
   - Account deletion option

3. **Item Categorization**:

   - Add categories or tags to items
   - Filtering and searching functionality

4. **Activity Logging**:

   - Track user actions
   - Display activity history

5. **Pagination and Sorting**:
   - Implement pagination for item lists
   - Add sorting options (date, alphabetical, etc.)

---

## Running and Testing the Application

1. Initialize the database:

   ```bash
   npm run init-db
   ```

2. Start the development server:

   ```bash
   npm run dev
   ```

3. Access the application at http://localhost:3000

---

## Conclusion

This comprehensive CRUD application provides a solid foundation with:

- Secure user authentication using NextAuth.js
- Complete CRUD operations for items with user-specific data isolation
- SQLite database integration with prepared statements for security
- Responsive UI with Tailwind CSS
- TypeScript for improved type safety
- Middleware for route protection

You can extend this application further by implementing the additional features mentioned above and adapting it to your specific requirements.

---

## Next Steps

To further enhance this application, consider implementing:

1. Testing

Unit tests for API endpoints
Integration tests for authentication flow
End-to-end tests for critical user journeys

2. Advanced Features

Email verification for new accounts
Two-factor authentication
Social login options
More advanced permissions system

3. Performance Optimizations

Server-side caching strategies
Optimized database queries
Image optimization if you add image uploads

---

This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.

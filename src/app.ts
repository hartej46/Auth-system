import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import useragent from "express-useragent";
import authRouter from "./routes/auth.routes.ts";

const app = express();

app.use(
    cors({
        origin: process.env.CORS_ORIGIN || "http://localhost:3000",
        credentials: true,
        exposedHeaders: ["x-Access-Token", "Authorization"],
    })
);

app.use(useragent.express());
app.use(
    express.json({
        limit: "16kb",
        verify: (req, _res, buffer) => {
            (req as typeof req & { rawBody?: Buffer }).rawBody = buffer;
        },
    })
);
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(cookieParser());

// Health Check
app.get("/health", (_req, res) => {
    return res.status(200).json({
        status: "ok",
        service: "Auth System",
        timestamp: new Date().toISOString(),
    });
});

// Authentication System Routes
app.use("/api/auth", authRouter);

// 404 Handler
app.use((_req, res) => {
    return res.status(404).json({
        success: false,
        message: "Endpoint not found",
    });
});

// Global Fallback Error Handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const statusCode = err.status || err.statusCode || 500;
    return res.status(statusCode).json({
        success: false,
        message: err.message || "Internal server error",
    });
});

export default app;

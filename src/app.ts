import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth";

export function createApp() {
    const app = express();

    app.use(cors({ origin: true, credentials: true }));
    app.use(express.json());
    app.use(cookieParser());
    app.use("/auth", authRoutes);

    app.get("/health", (_req, res) => {
        res.status(200).json({ ok: true });
    });

    return app;
}
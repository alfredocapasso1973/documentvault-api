import { describe, it, expect } from "vitest";
import request from "supertest";
import { createApp } from "../src/app";
import "dotenv/config";

process.env.DATABASE_URL = process.env.DATABASE_URL_TEST;
describe("GET /health", () => {
    it("returns ok", async () => {
        const app = createApp();
        const res = await request(app).get("/health");
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ ok: true });
    });
});
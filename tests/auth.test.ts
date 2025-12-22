import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import "dotenv/config";
async function makeApp() {
    const mod = await import("../src/app");
    return mod.createApp();
}

process.env.DATABASE_URL = process.env.DATABASE_URL_TEST;
const prisma = new PrismaClient();

beforeEach(async () => {
    await prisma.refreshToken.deleteMany();
    await prisma.document.deleteMany();
    await prisma.user.deleteMany();
});

afterAll(async () => {
    await prisma.$disconnect();
});

describe("POST /auth/register", () => {
    const creds = { email: "a@test.com", password: "Passw0rd!" };
    it("returns 201 and user payload", async () => {
        const app = await makeApp();

        const res = await request(app)
            .post("/auth/register")
            .send(creds);

        expect(res.status).toBe(201);
        expect(res.body.user).toMatchObject({ email: creds.email });
        expect(res.body.user.password).toBeUndefined();
        expect(typeof res.body.accessToken).toBe("string");
    });

    it("returns 409 if email already exists", async () => {
        const app = await makeApp();

        await request(app).post("/auth/register").send(creds);
        const res = await request(app).post("/auth/register").send(creds);

        expect(res.status).toBe(409);
    });

    it("returns 400 for invalid payload", async () => {
        const app = await makeApp();

        const res = await request(app)
            .post("/auth/register")
            .send({ email: "not-an-email", password: "123" });

        expect(res.status).toBe(400);
    });
});

describe("POST /auth/login", () => {
    const creds = { email: "login@test.com", password: "Passw0rd!" };
    const wrong = { email: "login@test.com", password: "WrongPassw0rd!" };
    it("returns 200 and accessToken for valid credentials", async () => {
        const app = await makeApp();

        const passwordHash = await bcrypt.hash(creds.password, 12);
        await prisma.user.create({
            data: { email: creds.email, password: passwordHash },
        });

        const res = await request(app)
            .post("/auth/login")
            .send(creds);

        expect(res.status).toBe(200);
        expect(typeof res.body.accessToken).toBe("string");
        expect(res.body.user).toMatchObject({ email: creds.email });
    });

    it("returns 401 for wrong password", async () => {
        const app = await makeApp();

        const passwordHash = await bcrypt.hash(creds.password, 12);
        await prisma.user.create({ data: { email: creds.email, password: passwordHash } });

        const res = await request(app).post("/auth/login").send(wrong);

        expect(res.status).toBe(401);
    });
});

describe("POST /auth/logout", () => {
    it("returns 204 and clears refresh cookie", async () => {
        const app = await makeApp();

        const res = await request(app).post("/auth/logout");

        expect(res.status).toBe(204);

        const setCookieHeader = res.headers["set-cookie"];
        const setCookie = Array.isArray(setCookieHeader) ? setCookieHeader.join(";") : (setCookieHeader || "");
        expect(setCookie).toContain("refreshToken=");
    });
});

describe("POST /auth/refresh", () => {
    const creds = { email: "refresh@test.com", password: "Passw0rd!" };

    it("returns 200 and new accessToken when refresh cookie is valid", async () => {
        const app = await makeApp();

        const loginRes = await request(app).post("/auth/register").send(creds);
        expect(loginRes.status).toBe(201);

        const refreshCookieHeader = loginRes.headers["set-cookie"];
        const cookieStr = Array.isArray(refreshCookieHeader)
            ? refreshCookieHeader.join(";")
            : (refreshCookieHeader || "");

        const res = await request(app)
            .post("/auth/refresh")
            .set("Cookie", cookieStr);

        expect(res.status).toBe(200);
        expect(typeof res.body.accessToken).toBe("string");
    });

    it("returns 401 when refresh cookie is missing", async () => {
        const app = await makeApp();

        const res = await request(app).post("/auth/refresh");
        expect(res.status).toBe(401);
    });
});
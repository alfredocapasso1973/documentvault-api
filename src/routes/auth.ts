import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { prisma } from "../db/prisma";
import { SignJWT } from "jose";
import crypto from "crypto";

const ACCESS_TTL = "15m";
const REFRESH_DAYS = 30;

function hashToken(token: string) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function newRefreshToken() {
    return crypto.randomBytes(32).toString("base64url");
}

async function issueRefreshToken(res: any, userId: string) {
    const refreshToken = newRefreshToken();
    const refreshTokenHash = hashToken(refreshToken);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_DAYS);

    await prisma.refreshToken.create({
        data: { userId, tokenHash: refreshTokenHash, expiresAt },
    });

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        path: "/auth/refresh",
        maxAge: REFRESH_DAYS * 24 * 60 * 60 * 1000,
    });
}

const router = Router();

const RegisterSchema = z.object({
    email: z.email(),
    password: z.string().min(8),
});

const LoginSchema = z.object({
    email: z.email(),
    password: z.string().min(1),
});

router.post("/register", async (req, res) => {
    const parsed = RegisterSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ error: "invalid_payload" });
    }

    const { email, password } = parsed.data;

    try {
        const passwordHash = await bcrypt.hash(password, 12);

        const user = await prisma.user.create({
            data: { email, password: passwordHash },
            select: { id: true, email: true, createdAt: true },
        });

        const secret = new TextEncoder().encode(process.env.JWT_SECRET || "");
        if (!secret.length) {
            return res.status(500).json({ error: "missing_jwt_secret" });
        }

        const accessToken = await new SignJWT({ email: user.email })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(user.id)
            .setIssuedAt()
            .setExpirationTime("15m")
            .sign(secret);

        await issueRefreshToken(res, user.id);

        return res.status(201).json({ user, accessToken });
    } catch (e: any) {
        if (e?.code === "P2002") {
            return res.status(409).json({ error: "email_taken" });
        }
        return res.status(500).json({ error: "internal_error" });
    }
});

router.post("/login", async (req, res) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ error: "invalid_payload" });
    }

    const { email, password } = parsed.data;

    const user = await prisma.user.findUnique({
        where: { email },
        select: { id: true, email: true, password: true, createdAt: true },
    });

    if (!user) {
        return res.status(401).json({ error: "invalid_credentials" });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
        return res.status(401).json({ error: "invalid_credentials" });
    }

    const secret = new TextEncoder().encode(process.env.JWT_SECRET || "");
    if (!secret.length) {
        return res.status(500).json({ error: "missing_jwt_secret" });
    }

    const accessToken = await new SignJWT({ email: user.email })
        .setProtectedHeader({ alg: "HS256" })
        .setSubject(user.id)
        .setIssuedAt()
        .setExpirationTime(ACCESS_TTL)
        .sign(secret);

    await issueRefreshToken(res, user.id);

    return res.status(200).json({
        user: { id: user.id, email: user.email, createdAt: user.createdAt },
        accessToken,
    });
});

router.post("/logout", async (_req, res) => {
    res.cookie("refreshToken", "", {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        path: "/auth/refresh",
        maxAge: 0,
    });

    return res.sendStatus(204);
});

router.post("/refresh", async (req, res) => {
    const token = req.cookies?.refreshToken;
    if (!token) {
        return res.status(401).json({ error: "missing_refresh_token" });
    }

    const tokenHash = hashToken(token);

    const row = await prisma.refreshToken.findFirst({
        where: {
            tokenHash,
            revokedAt: null,
            expiresAt: { gt: new Date() },
        },
        select: { userId: true, user: { select: { id: true, email: true, createdAt: true } } },
    });

    if (!row) {
        return res.status(401).json({ error: "invalid_refresh_token" });
    }

    const secret = new TextEncoder().encode(process.env.JWT_SECRET || "");
    if (!secret.length) {
        return res.status(500).json({ error: "missing_jwt_secret" });
    }

    const accessToken = await new SignJWT({ email: row.user.email })
        .setProtectedHeader({ alg: "HS256" })
        .setSubject(row.user.id)
        .setIssuedAt()
        .setExpirationTime(ACCESS_TTL)
        .sign(secret);

    return res.status(200).json({ user: row.user, accessToken });
});

export default router;
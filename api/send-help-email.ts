import type { IncomingMessage, ServerResponse } from "http";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";

type Body = {
    message?: string;
    userEmail?: string;
    userId?: string;
    appVersion?: string;
    platform?: string;
    screen?: string;
};

const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 5;
const ipHits = new Map<string, { count: number; resetAt: number }>();

function getIp(req: any): string {
    const xff = (req.headers["x-forwarded-for"] as string | undefined) ?? "";
    const ip = xff.split(",")[0]?.trim();
    return ip || req.socket?.remoteAddress || "unknown";
}

function setCors(req: any, res: any) {
    const origin = req.headers.origin as string | undefined;

    const allowed = process.env.ALLOWED_ORIGINS
        ? process.env.ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)
        : null;

    const allowOrigin = !allowed
        ? "*"
        : origin && allowed.includes(origin)
            ? origin
            : allowed[0] ?? "null";

    res.setHeader("Access-Control-Allow-Origin", allowOrigin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function sendJson(res: any, status: number, payload: Record<string, unknown>) {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(payload));
}

function normalizeEmail(email?: string): string | undefined {
    if (!email) return undefined;
    const trimmed = email.trim();
    if (!trimmed) return undefined;
    const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
    return ok ? trimmed : undefined;
}

export default async function handler(req: IncomingMessage & any, res: ServerResponse & any) {
    setCors(req, res);

    if (req.method === "OPTIONS") {
        res.statusCode = 204;
        return res.end();
    }

    if (req.method !== "POST") {
        return sendJson(res, 405, { error: "Method not allowed" });
    }

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
        return sendJson(res, 500, { error: "Server auth config is missing." });
    }

    const authHeader = (req.headers.authorization as string | undefined) ?? "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
        return sendJson(res, 401, { error: "Missing Authorization Bearer token." });
    }

    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: userData, error: userErr } = await supabaseAdmin.auth.getUser(token);
    if (userErr || !userData?.user) {
        return sendJson(res, 401, { error: "Invalid or expired token." });
    }

    const authedUserId = userData.user.id;
    const authedUserEmail = userData.user.email ?? undefined;

    const ip = getIp(req);
    const now = Date.now();
    const hit = ipHits.get(ip);
    if (!hit || hit.resetAt <= now) {
        ipHits.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    } else {
        hit.count += 1;
        if (hit.count > RATE_MAX) {
            return sendJson(res, 429, { error: "Too many requests. Please try again shortly." });
        }
    }

    let body: Body = {};
    try {
        if (typeof req.body === "string") body = JSON.parse(req.body);
        else if (req.body && typeof req.body === "object") body = req.body;
        else body = {};
    } catch {
        return sendJson(res, 400, { error: "Invalid JSON body" });
    }

    const message = (body.message ?? "").trim();
    const appVersion = (body.appVersion ?? "").toString().trim() || undefined;
    const platform = (body.platform ?? "").toString().trim() || undefined;
    const screen = (body.screen ?? "").toString().trim() || undefined;

    if (message.length < 10) {
        return sendJson(res, 400, { error: "Message must be at least 10 characters." });
    }
    if (message.length > 5000) {
        return sendJson(res, 400, { error: "Message is too long." });
    }

    const GMAIL_USER = process.env.GMAIL_USER;
    const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;
    const SUPPORT_TO_EMAIL = process.env.SUPPORT_TO_EMAIL || GMAIL_USER;

    if (!GMAIL_USER || !GMAIL_APP_PASSWORD || !SUPPORT_TO_EMAIL) {
        return sendJson(res, 500, { error: "Server email config is missing." });
    }

    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: GMAIL_USER,
            pass: GMAIL_APP_PASSWORD,
        },
    });

    const subject = "Help request (App)";
    const text =
        `New help request\n\n` +
        `User email: ${authedUserEmail ?? "unknown"}\n` +
        `User ID: ${authedUserId}\n` +
        `Platform: ${platform ?? "unknown"}\n` +
        `App version: ${appVersion ?? "unknown"}\n` +
        `Screen: ${screen ?? "unknown"}\n` +
        `IP: ${ip}\n\n` +
        `Message:\n${message}\n`;

    try {
        const info = await transporter.sendMail({
            from: `"App Support" <${GMAIL_USER}>`,
            to: SUPPORT_TO_EMAIL,
            subject,
            text,
            replyTo: normalizeEmail(authedUserEmail),
        });

        return sendJson(res, 200, { ok: true, messageId: info.messageId });
    } catch (err: any) {
        return sendJson(res, 502, {
            error: "Failed to send email",
            detail: err?.message ? String(err.message) : "Unknown error",
        });
    }
}

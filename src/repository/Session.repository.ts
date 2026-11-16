import Query from "../db/query.ts";
import AppError from "../utils/error.ts";
import type { PoolClient } from "pg";
import { Session } from "../models/Session.model.ts";

/**
 * Creates the sessions table and associated indexes.
 * Cascades on user deletion.
 */
export const createSessionTable = async (): Promise<void> => {
    const query = `
        CREATE TABLE IF NOT EXISTS sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id INTEGER NOT NULL,
            ip_address INET NOT NULL,
            user_agent TEXT,
            device_name VARCHAR(100),
            csrf_secret TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            revoked_reason TEXT,
            CONSTRAINT fk_sessions_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user_id
            ON sessions(user_id);

        CREATE INDEX IF NOT EXISTS idx_sessions_active
            ON sessions(user_id, expires_at)
            WHERE revoked_at IS NULL;
    `;

    try {
        await Query(query, []);
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while creating table sessions";
        throw new AppError(errorMessage, 500);
    }
};

export const createSessionWithClient = async (
    client: PoolClient,
    userId: string | number,
    ipAddress: string,
    csrfSecret: string,
    expiresAt: Date,
    userAgent: string | null = null,
    deviceName: string | null = null
): Promise<Session> => {
    const query = `
        INSERT INTO sessions (
            user_id, ip_address, user_agent, device_name, csrf_secret, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6
        ) RETURNING *;
    `;

    const res = await client.query(query, [
        String(userId),
        ipAddress,
        userAgent,
        deviceName,
        csrfSecret,
        expiresAt,
    ]);

    return res.rows[0] || null;
};

export const createSession = async (
    userId: string | number,
    ipAddress: string,
    csrfSecret: string,
    expiresAt: Date,
    userAgent: string | null = null,
    deviceName: string | null = null
): Promise<Session> => {
    const query = `
        INSERT INTO sessions (
            user_id, ip_address, user_agent, device_name, csrf_secret, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6
        ) RETURNING *;
    `;

    try {
        const res = await Query(query, [
            String(userId),
            ipAddress,
            userAgent,
            deviceName,
            csrfSecret,
            expiresAt,
        ]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while creating session";
        throw new AppError(errorMessage, 500);
    }
};

export const getSessionById = async (
    id: string,
    userId?: string | number
): Promise<Session | null> => {
    const query = userId
        ? `SELECT * FROM sessions WHERE id = $1 AND user_id = $2;`
        : `SELECT * FROM sessions WHERE id = $1;`;

    try {
        const res = await Query(query, userId ? [id, String(userId)] : [id]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while getting session";
        throw new AppError(errorMessage, 500);
    }
};

export const getSessionsByUserId = async (userId: string | number): Promise<Session[]> => {
    const query = `
        SELECT id, user_id, ip_address, user_agent, device_name, created_at, last_used_at, expires_at, revoked_at, revoked_reason
        FROM sessions 
        WHERE user_id = $1 
        ORDER BY created_at DESC;
    `;

    try {
        const res = await Query(query, [String(userId)]);
        return res.rows;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while getting user sessions";
        throw new AppError(errorMessage, 500);
    }
};

export const updateSessionById = async (
    id: string,
    userId: string | number,
    csrfSecret: string,
    expiresAt: Date
): Promise<Session | null> => {
    const query = `
        UPDATE sessions 
        SET csrf_secret = $1,
            expires_at = $2,
            last_used_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3 AND user_id = $4 AND revoked_at IS NULL
        RETURNING *;
    `;

    try {
        const res = await Query(query, [csrfSecret, expiresAt, id, String(userId)]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while updating session";
        throw new AppError(errorMessage, 500);
    }
};

export const revokeSessionById = async (
    id: string,
    userId: string | number,
    reason: string = "logout"
): Promise<Session | null> => {
    const query = `
        UPDATE sessions
        SET revoked_at = CURRENT_TIMESTAMP,
            revoked_reason = $1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL
        RETURNING *;
    `;

    try {
        const res = await Query(query, [reason, id, String(userId)]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while revoking session";
        throw new AppError(errorMessage, 500);
    }
};

export const revokeAllSessions = async (
    userId: string | number,
    reason: string = "logout_all"
): Promise<Session[]> => {
    const query = `
        UPDATE sessions
        SET revoked_at = CURRENT_TIMESTAMP,
            revoked_reason = $1,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = $2 AND revoked_at IS NULL
        RETURNING *;
    `;

    try {
        const res = await Query(query, [reason, String(userId)]);
        return res.rows;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while revoking all sessions";
        throw new AppError(errorMessage, 500);
    }
};

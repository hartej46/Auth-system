import Query from "../db/query.ts";
import AppError from "../utils/error.ts";
import { hashPassword } from "../utils/password.ts";
import type { PoolClient } from "pg";
import { User, UserWithPassword } from "../models/User.model.ts";

/**
 * Creates user PostgreSQL table and necessary indexes.
 * The query is idempotent (safe to run on every startup).
 */
export const createTableUser = async (): Promise<void> => {
    const query = `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `;

    try {
        await Query(query, []);
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while creating table users";
        throw new AppError(errorMessage, 500);
    }
};

export const createUserWithClient = async (
    client: PoolClient,
    name: string,
    email: string,
    password: string,
    is_verified: boolean = true
): Promise<User> => {
    const query = `
        INSERT INTO users (name, email, password, is_verified)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, email, is_verified, created_at, updated_at, last_login;
    `;

    const res = await client.query(query, [name, email, password, is_verified]);
    return res.rows[0] || null;
};

export const createUser = async (
    name: string,
    email: string,
    password: string,
    is_verified: boolean = true
): Promise<User> => {
    const query = `
        INSERT INTO users (name, email, password, is_verified)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, email, is_verified, created_at, updated_at, last_login;
    `;

    try {
        const res = await Query(query, [name, email, password, is_verified]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while creating user";
        throw new AppError(errorMessage, 500);
    }
};

export const getUserDetailsById = async (id: string | number): Promise<User | null> => {
    const query = `
        SELECT id, name, email, is_verified, created_at, updated_at, last_login 
        FROM users 
        WHERE id = $1;
    `;

    try {
        const res = await Query(query, [String(id)]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while getting user by id";
        throw new AppError(errorMessage, 500);
    }
};

export const getUserByEmail = async (email: string): Promise<User | null> => {
    const query = `
        SELECT id, name, email, is_verified, created_at, updated_at, last_login 
        FROM users 
        WHERE email = $1;
    `;

    try {
        const res = await Query(query, [email]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while fetching user by email";
        throw new AppError(errorMessage, 500);
    }
};

export const getUserByEmailWithPassword = async (
    email: string
): Promise<UserWithPassword | null> => {
    const query = `SELECT * FROM users WHERE email = $1 LIMIT 1;`;

    try {
        const res = await Query(query, [email]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while fetching user credentials";
        throw new AppError(errorMessage, 500);
    }
};

export const updateUserLoginWithClient = async (
    client: PoolClient,
    id: string | number
): Promise<User> => {
    const query = `
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING id, name, email, is_verified, created_at, updated_at, last_login;
    `;

    const res = await client.query(query, [String(id)]);
    return res.rows[0] || null;
};

export const updateUserLogin = async (id: string | number): Promise<User> => {
    const query = `
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING id, name, email, is_verified, created_at, updated_at, last_login;
    `;

    try {
        const res = await Query(query, [String(id)]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while updating last login";
        throw new AppError(errorMessage, 500);
    }
};

export const updatePassword = async (
    id: string | number,
    newPassword: string
): Promise<User | null> => {
    const hashedPassword = await hashPassword(newPassword);
    const query = `
        UPDATE users 
        SET password = $1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        RETURNING id, name, email, is_verified, updated_at;
    `;

    try {
        const res = await Query(query, [hashedPassword, String(id)]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while updating password";
        throw new AppError(errorMessage, 500);
    }
};

export const updateProfile = async (id: string | number, name: string): Promise<User | null> => {
    const query = `
        UPDATE users 
        SET name = $1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        RETURNING id, name, email, is_verified, created_at, updated_at, last_login;
    `;

    try {
        const res = await Query(query, [name, String(id)]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while updating profile";
        throw new AppError(errorMessage, 500);
    }
};

export const deleteUser = async (id: string | number): Promise<User | null> => {
    const query = `DELETE FROM users WHERE id = $1 RETURNING id, name, email;`;

    try {
        const res = await Query(query, [String(id)]);
        return res.rows[0] || null;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Something went wrong while deleting user";
        throw new AppError(errorMessage, 500);
    }
};

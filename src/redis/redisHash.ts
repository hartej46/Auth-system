import redisClient from "../db/redis.ts";
import AppError from "../utils/error.ts";

export const setRedis = async (
    key: string,
    data: string,
    expiresInSeconds: number
): Promise<void> => {
    if (!key.trim()) throw new Error("Redis key is required");

    if (!Number.isInteger(expiresInSeconds) || expiresInSeconds <= 0) {
        throw new Error("Redis expiry must be a positive integer in seconds");
    }

    try {
        await redisClient.set(key, data, {
            EX: expiresInSeconds,
        });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while storing data in Redis";
        throw new AppError(errorMessage, 500);
    }
};

export const getRedis = async <T = any>(key: string): Promise<T | null> => {
    try {
        const data = await redisClient.get(key);
        if (!data || typeof data !== "string" || data.trim() === "") {
            return null;
        }

        return JSON.parse(data) as T;
    } catch (error: unknown) {
        if (error instanceof AppError) throw error;
        console.error(`Malformed or error reading Redis key "${key}":`, error);
        throw new AppError("Error accessing cache data", 500);
    }
};

export const deleteRedis = async (key: string): Promise<void> => {
    try {
        await redisClient.del(key);
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error
                ? error.message
                : "Something went wrong while deleting data from Redis";
        throw new AppError(errorMessage, 500);
    }
};

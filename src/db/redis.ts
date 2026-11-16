import { createClient } from "redis";

const client = createClient({
    username: process.env.REDIS_USERNAME || undefined,
    password: process.env.REDIS_PASSWORD || undefined,
    socket: {
        host: process.env.REDIS_HOST || "localhost",
        port: Number(process.env.REDIS_PORT) || 6379,
    },
});

client.on("error", (error) => {
    console.error("Redis client error:", error);
});

export const connectRedis = async (): Promise<void> => {
    try {
        if (!client.isOpen) {
            await client.connect();
            console.log("Redis connected successfully");
        }
    } catch (error) {
        console.error("Failed to connect to Redis:", error);
    }
};

export default client;

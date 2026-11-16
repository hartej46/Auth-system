import { Pool, type PoolClient, type PoolConfig } from "pg";
import "dotenv/config";

const connectionString: string | undefined = process.env.CONNECTION_STRING;

if (!connectionString && process.env.NODE_ENV !== "test") {
    console.warn("Warning: CONNECTION_STRING is not defined in environment variables.");
}

const isProduction: boolean = process.env.NODE_ENV === "production";
const hasSslQuery: boolean = connectionString
    ? connectionString.includes("sslmode=require") || connectionString.includes("ssl=true")
    : false;
const forceSsl = process.env.DB_SSL === "true";

const sslConfig: PoolConfig["ssl"] =
    isProduction || hasSslQuery || forceSsl ? { rejectUnauthorized: false } : false;

const pool = new Pool({
    connectionString: connectionString || undefined,
    ssl: sslConfig,
});

export const withTransaction = async <T>(
    callback: (client: PoolClient) => Promise<T>
): Promise<T> => {
    const client = await pool.connect();

    try {
        await client.query("BEGIN");
        const result = await callback(client);
        await client.query("COMMIT");
        return result;
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
};

export const connectDB = async (): Promise<void> => {
    try {
        const client = await pool.connect();
        console.log("PostgreSQL connection established successfully");
        client.release();
    } catch (error) {
        console.error("Failed to connect to PostgreSQL:", error);
    }
};

export default pool;

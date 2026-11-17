import "dotenv/config";
import app from "./app.ts";
import { connectDB } from "./db/db.ts";
import { connectRedis } from "./db/redis.ts";
import { createTableUser } from "./repository/User.repository.ts";
import { createSessionTable } from "./repository/Session.repository.ts";

const PORT = Number(process.env.PORT) || 8000;

/**
 * Initializes database tables idempotently.
 */
export const initDB = async (): Promise<void> => {
    await createTableUser();
    await createSessionTable();
    console.log("Database tables initialized successfully (users, sessions)");
};

// Bootstrap Server
(async () => {
    try {
        await connectDB();
        await connectRedis();
        await initDB();

        app.listen(PORT, () => {
            console.log(`🚀 Auth System server is running on http://localhost:${PORT}`);
        });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error while starting server";
        console.error("Failed to start server:", errorMessage);
        process.exit(1);
    }
})();

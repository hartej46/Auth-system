import pool from "./db.ts";

export type QueryParam = string | number | boolean | Date | null | string[] | number[];

const Query = async (text: string, params: QueryParam[] = []) => {
    const startTime = Date.now();
    try {
        const res = await pool.query(text, params);
        const duration = Date.now() - startTime;
        if (process.env.NODE_ENV !== "test") {
            console.log(`Query executed in ${duration}ms`);
        }
        return res;
    } catch (error: unknown) {
        console.error(
            `Database Query Error: ${error}\nExecution time: ${Date.now() - startTime}ms`
        );
        throw error;
    }
};

export default Query;

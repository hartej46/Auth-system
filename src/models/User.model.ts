export interface User {
    id: string;
    name: string;
    email: string;
    is_verified: boolean;
    created_at: Date;
    updated_at: Date;
    last_login: Date | null;
}

export interface UserWithPassword extends User {
    password: string;
}

export interface CreateUser {
    name: string;
    email: string;
    password: string;
    is_verified?: boolean;
}

export interface SignupDraft {
    name: string;
    email: string;
    password: string; // hashed
    otp: string;
    createdAt: string;
}

export interface JwtTokenPayload {
    userId: string;
    sessionId: string;
    email: string;
    name: string;
}

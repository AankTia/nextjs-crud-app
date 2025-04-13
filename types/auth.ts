export interface User {
    id: number;
    username: string;
    email: string;
    created_at: string;
}

export interface Creadentials {
    email: string;
    password: string;
}

export interface RegistrationData extends Creadentials {
    username: string;
}
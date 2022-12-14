export * from "./config";

export interface DockerErrorSchema {
    errors: ({
        code: string,
        message: string,
        detail: any,
    })[]
}

export interface RequestContext {
    allowedRepos: Set<string>,
    username?: string
}

export interface DockerOAuth2Config {
    username: string;
    password: string;
    regitryUrl: string;
    fallbackValidity?: number;
    forceScope?: string;
    clientId?: string;
}

export interface DockerOAuth2TokenRequest {
    grant_type: "password" | "refresh_token" | "authorization_code",
    service: string,
    client_id: string,
    access_type?: "offline" | "online",
    scope?: string,
    refresh_token?: string,
    username?: string,
    password?: string
}

export interface DockerTokenRequest {
    service: string,
    client_id?: string,
    scope: string,
    offline_token: boolean,
}

export interface LocalOAuth2TokenData {
    t: "r" | "a",
    un: string
}
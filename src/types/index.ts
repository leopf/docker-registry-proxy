export * from "./config";

export interface DockerErrorSchema {
    errors: ({
        code: string,
        message: string,
        detail: any,
    })[]
}

export interface RequestContext {
    allowedRepos: Set<string>
}

export interface OAuth2Config {
    username: string;
    password: string;
    regitryUrl: string;
    fallbackValidity?: number;
    forceScope?: string;
    clientId?: string;
}
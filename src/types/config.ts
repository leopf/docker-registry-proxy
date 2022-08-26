export interface BearerAccessToken {
    token: string;
    validUntil: Date;
}

export interface RemoteAuthenticationBasic {
    type: "basic",
    username: string;
    password: string;
}

export interface RemoteAuthenticationBearer {
    type: "oauth2",
    username: string;
    password: string;

    fallbackValidity?: number;
    forceScope?: string;
    clientId?: string;
}

export type RemoteAuthentication = RemoteAuthenticationBasic | RemoteAuthenticationBearer;

export type AuthenticationScope = null | undefined | string[]; // null or undefined means the authentication failed!

export interface LocalAuthenticationBasic {
    type: "basic",
    authenticate: (username: string, password: string) => Promise<AuthenticationScope>
}

export interface LocalAuthenticationOAuth {
    type: "oauth",
    jwtSecret: string | Buffer;
    service: string,
    tokenLifetime: number,
    useHttps?: boolean,
    authenticate: (username: string, password: string) => Promise<boolean>,
    resolveRepositories: (username: string) => Promise<AuthenticationScope>
}

export interface LocalAuthenticationNone {
    type: "none",
    scope: AuthenticationScope;
}

export type LocalAuthentication = LocalAuthenticationBasic | LocalAuthenticationNone | LocalAuthenticationOAuth;

export interface ProxyConfig {
    realm: string,

    remoteRegistryUrl: string,
    remoteAuthentication?: RemoteAuthentication;

    localAuthentication: LocalAuthentication;
}

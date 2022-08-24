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
    type: "bearer",
    resolveToken: () => Promise<BearerAccessToken>
}

export type RemoteAuthentication = RemoteAuthenticationBasic | RemoteAuthenticationBearer;

export type AuthenticationScope = null | undefined | string[]; // null or undefined means the authentication failed!

export interface LocalAuthenticationBasic {
    type: "basic",
    authenticate: (username: string, password: string) => Promise<AuthenticationScope>
}

export interface LocalAuthenticationNone {
    type: "none",
    scope: AuthenticationScope;
}

export type LocalAuthentication = LocalAuthenticationBasic | LocalAuthenticationNone;

export interface ProxyConfig {
    realm: string,

    remoteRegistryUrl: string,
    remoteAuthentication?: RemoteAuthentication;

    localAuthentication: LocalAuthentication;
}

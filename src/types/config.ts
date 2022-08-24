export interface RemoteAuthenticationBasic {
    type: "basic",
    username: string;
    password: string;
}

export type RemoteAuthentication = RemoteAuthenticationBasic;

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
    realmName: string,

    remoteRegistryUrl: string,
    remoteAuthentication?: RemoteAuthentication;

    localAuthentication: LocalAuthentication;
}

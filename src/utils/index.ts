import urljoin from "url-join";
import { BearerAccessToken, RemoteAuthentication } from "../types";
import fetch from 'cross-fetch';
import { createBasicAuthHeaderValue } from "./basic-auth";
import { oauthGetToken } from "./remote-oauth2";

export * from "./validation";
export * from "./local-oauth2";

export function createAuthenticatedFetcher(remoteRegistryUrl: string, remoteAuthentication?: RemoteAuthentication) {
    if (remoteAuthentication?.type === "basic") {
        return async (suffix: string, options: { method?: string, headers?: Record<string, string> } = {}) => {
            try {
                return await fetch(urljoin(remoteRegistryUrl, suffix), {
                    method: options.method || "get",
                    headers: {
                        ...(options.headers || {}),
                        "authorization": createBasicAuthHeaderValue(remoteAuthentication.username, remoteAuthentication.password)
                    }
                });
            } catch {
                throw new Error("Failed requesting reqource from remote registry!");
            }
        };
    }
    else if (remoteAuthentication?.type === "oauth2") {
        let token : BearerAccessToken | undefined = undefined;
        return async (suffix: string, options: { method?: string, headers?: Record<string, string> } = {}) => {
            try {
                if (token === undefined || token.validUntil.getTime() < (new Date()).getTime()) {
                    token = await oauthGetToken({
                        username: remoteAuthentication.username,
                        password: remoteAuthentication.password,
                        regitryUrl: remoteRegistryUrl,
                        clientId: remoteAuthentication.clientId,
                        fallbackValidity: remoteAuthentication.fallbackValidity,
                        forceScope: remoteAuthentication.forceScope,
                    });
                }

                return await fetch(urljoin(remoteRegistryUrl, suffix), {
                    method: options.method || "get",
                    headers: {
                        ...(options.headers || {}),
                        "authorization": `bearer ${token.token}`
                    }
                });
            } catch {
                throw new Error("Failed requesting reqource from remote registry!");
            }
        };
    }

    return async (suffix: string, options: { method?: string, headers?: Record<string, string> } = {}) => {
        try {
            return await fetch(urljoin(remoteRegistryUrl, suffix), {
                method: options.method || "get",
                headers: options.headers
            });
        } catch {
            throw new Error("Failed requesting reqource from remote registry!");
        }
    };
}
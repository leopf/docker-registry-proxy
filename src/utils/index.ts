import urljoin from "url-join";
import { BearerAccessToken, RemoteAuthentication } from "../types";
import fetch from 'cross-fetch';

export * from "./validation";

export function createAuthenticatedFetcher(remoteRegistryUrl: string, remoteAuthentication?: RemoteAuthentication) {
    if (remoteAuthentication?.type === "basic") {
        return async (suffix: string, options: { method?: string, headers?: Record<string, string> } = {}) => {
            try {
                return await fetch(urljoin(remoteRegistryUrl, suffix), {
                    method: options.method || "get",
                    headers: {
                        ...(options.headers || {}),
                        "authorization": `basic ${Buffer.from(
                            remoteAuthentication.username +
                            ':' +
                            remoteAuthentication.password).toString('base64')}`
                    }
                });
            } catch {
                throw new Error("Failed requesting reqource from remote registry!");
            }
        };
    }
    else if (remoteAuthentication?.type === "bearer") {
        let token : BearerAccessToken | undefined = undefined;
        return async (suffix: string, options: { method?: string, headers?: Record<string, string> } = {}) => {
            try {
                if (token === undefined || token.validUntil.getTime() < (new Date()).getTime()) {
                    token = await remoteAuthentication.resolveToken();
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
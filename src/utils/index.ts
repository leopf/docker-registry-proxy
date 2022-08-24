import urljoin from "url-join";
import { RemoteAuthentication } from "../types";
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
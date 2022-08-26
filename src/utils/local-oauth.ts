import { LocalAuthenticationOAuth } from "../types";
import jws from "jsonwebtoken";

function createRealmFromConfig(service: string, useHttps: boolean) {
    return `http${useHttps ? "s" : ""}://${service}/token`
}

export const defaultScope = "repository:user/image:pull";

export function createOauthWwwAuthenticateFromConfig(config: LocalAuthenticationOAuth) {
    const realm = createRealmFromConfig(config.service, !!config.useHttps);
    const service = config.service;
    const scope = defaultScope;

    return `bearer realm="${realm}",service="${service}",scope="${scope}"`;
}

export function extractTokenFromAuthHeader(values: string[]) : string | undefined {
    const foundHeader = values.find(value => value.toLocaleLowerCase().startsWith("bearer "));

    if (foundHeader) {
        return foundHeader.slice(7).trim();
    }
    else {
        return undefined;
    }
}

export function extractRepositoriesFromToken(token: string, jwtSecret: string | Buffer)  {
    const tokenData = jws.verify(token, jwtSecret);
    if (typeof tokenData === "string") {
        return undefined;
    }

    if (Array.isArray(tokenData.repos)) {
        const validRepos = tokenData.repos.filter(repo => typeof repo === "string");
        return validRepos as string[];
    }
    else {
        return undefined;
    }
}

export function createTokenWithRepositories(repos: string[], jwtSecret: string | Buffer) {
    return jws.sign({
        repos: new Set(repos.filter(repo => typeof repo === "string"))
    }, jwtSecret);  
}
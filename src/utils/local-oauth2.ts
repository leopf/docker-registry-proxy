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

export function extractUsernameFromToken(token: string, jwtSecret: string | Buffer)  {
    const tokenData = jws.verify(token, jwtSecret);
    if (typeof tokenData === "string") {
        return undefined;
    }

    if (typeof tokenData.un === "string") {
        return tokenData.un;
    }
    else {
        return undefined;
    }
}

export function createTokenForUser(username: string, jwtSecret: string | Buffer, lifetime: number) {
    if (typeof lifetime !== "number") {
        throw new Error("Invalid lifetime parameter!");
    }

    return jws.sign({
        un: username
    }, jwtSecret, {
        expiresIn: lifetime
    });  
}
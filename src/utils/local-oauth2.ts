import { LocalAuthenticationOAuth, LocalOAuth2TokenData } from "../types";
import jwt from "jsonwebtoken";
import { validateLocalOAuth2TokenData } from "./validation";
import { AuthenticationError } from "../errors";

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

export function extractDataFromToken(token: string, jwtSecret: string | Buffer) : LocalOAuth2TokenData {
    const tokenData = jwt.verify(token, jwtSecret);
    if (typeof tokenData === "string") {
        throw new AuthenticationError("Invalid token data!");
    }
    
    const oauthTokenData = tokenData as LocalOAuth2TokenData;

    validateLocalOAuth2TokenData(oauthTokenData);

    return {
        t: oauthTokenData.t,
        un: oauthTokenData.un
    };
}

export function createTokenWithData(data: LocalOAuth2TokenData, jwtSecret: string | Buffer, lifetime: number | undefined) {
    if (lifetime !== undefined && typeof lifetime !== "number") {
        throw new Error("Invalid lifetime parameter!");
    }

    try {
        validateLocalOAuth2TokenData(data);        
    } catch {
        throw new Error("Invalid token data generated from config!");
    }

    let options: jwt.SignOptions = {};
    if (lifetime !== undefined) {
        options.expiresIn = lifetime;
    }

    return jwt.sign(data, jwtSecret, options);  
}
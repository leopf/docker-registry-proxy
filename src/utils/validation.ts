import { AuthenticationError, DigestInvalidError, RepositoryNameInvalidError, TagInvalidError } from "../errors";
import { DockerOAuth2TokenRequest, LocalAuthenticationOAuth, LocalOAuth2TokenData } from "../types";
import validator from "validator";

export function validateDigest(digest: string) {
    if (digest.length > 1024 || !/([A-Fa-f0-9_+.-]+):([A-Fa-f0-9]+)/.test(digest)) {
        throw new DigestInvalidError("The given digest is invalid!");
    }
}

export function validateTag(tag: string) {
    if (tag.length > 128 || !/[a-zA-Z0-9_][a-zA-Z0-9_\.\-]*/.test(tag)) {
        throw new TagInvalidError("The gived tag is invalid!");
    }
}

export function validateRepositoryName(repoName: string) {
    if (repoName.length < 2 || 
            repoName.length > 255 || 
            repoName.split("/").some(repoNameComponent => !/[a-z0-9]+(?:[._-][a-z0-9]+)*/i.test(repoNameComponent))) {
        throw new RepositoryNameInvalidError("The given repository name is invalid!");
    }
}

export function validateTokenRequest(tokenRequest: DockerOAuth2TokenRequest, config: LocalAuthenticationOAuth) {
    if (tokenRequest.service !== config.service) {
        throw new AuthenticationError("service not supported!");
    }
}

export function validateTokenRequestRefreshToken(tokenRequest: DockerOAuth2TokenRequest) {
    if (!tokenRequest.refresh_token || typeof tokenRequest.refresh_token !== "string") {
        throw new AuthenticationError("missing refresh_token!");
    }
}


export function validateTokenRequestPassword(tokenRequest: DockerOAuth2TokenRequest) {
    if (!tokenRequest.username || typeof tokenRequest.username !== "string") {
        throw new AuthenticationError("missing username!");
    }

    if (!tokenRequest.password || typeof tokenRequest.password !== "string") {
        throw new AuthenticationError("missing password!");
    }
}

export function validateLocalAuthenticationOAuth(auth: LocalAuthenticationOAuth) {
    const serviceParts = auth.service.split(":");

    if (serviceParts.length !== 2 && serviceParts.length !== 1) {
        throw new Error("The service name must be a fqdn optionally followed by a port!");
    }

    if (!validator.isFQDN(serviceParts[0], { require_tld: false })) {
        throw new Error("The service name must be a fqdn optionally followed by a port!");
    }

    if (serviceParts.length === 2 && !validator.isPort(serviceParts[1])) {
        throw new Error("The service name must be a fqdn optionally followed by a port!");
    }

    if (typeof auth.tokenLifetime !== "number") {
        throw new Error("The token lifetime must be a number of seconds!");
    }

    if (typeof auth.useHttps !== "boolean") {
        throw new Error("The useHttps config must be a boolean!");
    }
}

export function validateLocalOAuth2TokenData(data: LocalOAuth2TokenData) {
    if (data.t !== "a" && data.t !== "r") {
        throw new AuthenticationError("invalid token data!");
    }
    if (typeof data.un !== "string") {
        throw new AuthenticationError("invalid token data!");
    }
}
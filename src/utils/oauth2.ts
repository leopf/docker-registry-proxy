import urljoin from "url-join";
import queryString from "query-string";
import { createBasicAuthHeaderValue } from "./basic-auth";
import { BearerAccessToken, DockerOAuth2Config, DockerOAuth2TokenRequest } from "../types";
import fetch from "cross-fetch";

function extractHeaderParam(name: string, header: string) {
    const match = (new RegExp(`^.*${name}=\"([^\"]+)\".*$`, "ig")).exec(header);
    return match?.[1];
}

async function oauthPingRepository(repoUrl: string) {
    const resPing = await fetch(urljoin(repoUrl, "/v2/"), {
        method: "get",
        headers: {
            accept: "application/json"
        }
    });

    const wwwAuthHeader: string | undefined = resPing.headers.get("www-authenticate") || undefined;
    const lcWwwAuthHeader = wwwAuthHeader?.toLocaleLowerCase();
    if (!wwwAuthHeader?.toLocaleLowerCase()?.startsWith("bearer")) {
        throw new Error("Expected bearer challange!");
    }

    const realm = extractHeaderParam("realm", wwwAuthHeader);
    const service = extractHeaderParam("service", wwwAuthHeader);
    const scope = extractHeaderParam("scope", wwwAuthHeader);

    if (!realm) {
        throw new Error("Expected realm parameter in www-authenticate challenge!");
    }

    let finalRealm = realm;
    if (!finalRealm.startsWith("http")) {
        finalRealm = "https://" + finalRealm;
    }

    return {
        realm: finalRealm,
        service,
        scope
    };
}

async function oauthGetTokenMethod1(config: DockerOAuth2Config) : Promise<BearerAccessToken> {
    const { scope, realm, service } = await oauthPingRepository(config.regitryUrl);

    const authData = await fetch(realm + "?" + queryString.stringify({
        account: config.username,
        scope: config.forceScope || scope,
        service: service
    }), {
        method: "get",
        headers: {
            accept: "application/json",
            authorization: createBasicAuthHeaderValue(config.username, config.password),
        }
    }).then(r => r.json());

    if (!authData?.token || typeof authData.token !== "string") {
        throw new Error("Access token not defined!");
    }

    return {
        token: authData.token,
        validUntil: new Date((new Date()).getTime() + (config.fallbackValidity || (1000 * 60 * 60)))
    };
}

async function oauthGetTokenMethod2(config: DockerOAuth2Config) : Promise<BearerAccessToken> {
    const { scope, realm, service } = await oauthPingRepository(config.regitryUrl);

    if (!service) {
        throw new Error("Service shall not be empty!");
    }

    const finalScope = config.forceScope || scope;
    
    const authData = await fetch(realm,{
        method: "post",
        body: new URLSearchParams({
            "grant_type": "password",
            "client_id": "registry-proxy" || config.clientId,
            "access_type": "online", // TODO offline support 
            ...(finalScope ? { scope: finalScope }: {}),
            ...(service ? { service }: {}),
            "username": config.username,
            "password": config.password
        }),
        headers: {
            accept: "application/json",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    }).then(r => r.json());

    let issuedAt: Date;
    if (typeof authData?.issued_at === "string") {
        issuedAt = new Date(authData.issued_at);
    }
    else {
        issuedAt = new Date();
    }

    if (typeof authData?.expires_in !== "number") {
        throw new Error("expires_in not defined!");
    }
    if (typeof authData?.access_token !== "string") {
        throw new Error("access_token not defined!");
    }

    const validUntil = new Date(issuedAt.getTime() + 1000 * authData.expires_in - 10000);

    return {
        token: authData.access_token,
        validUntil: validUntil
    };
}

export async function oauthGetToken(config: DockerOAuth2Config) {
    try {
        return await oauthGetTokenMethod1(config);
    } catch {
        return await oauthGetTokenMethod2(config);
    }
}
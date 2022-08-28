import express from "express";
import basicAuth from "basic-auth";
import { AuthenticationError, DigestInvalidError, ManifestUnknownError, RepositoryNameInvalidError, RepositoryNotFoundError, TagInvalidError } from "./errors";
import KoaRouter from "@koa/router";
import { DockerErrorSchema, DockerOAuth2TokenRequest, DockerTokenRequest, ProxyConfig, RequestContext } from "./types";
import { createAuthenticatedFetcher, createOauthWwwAuthenticateFromConfig, createTokenWithData, defaultScope, extractDataFromToken, extractTokenFromAuthHeader, validateDigest, validateLocalAuthenticationOAuth, validateRepositoryName, validateTag, validateOAuth2TokenRequest as validateOAuth2TokenRequest, validateTokenRequestPassword, validateTokenRequestRefreshToken, validateTokenRequest } from "./utils";
import bodyParser from "koa-body";

export * from "./types/config";

export function createRouter(config: ProxyConfig) {

    const authReqRR = createAuthenticatedFetcher(config.remoteRegistryUrl, config.remoteAuthentication);

    const router = new KoaRouter<RequestContext>();

    router.use(["/v2/", "/token"], async (ctx, next: express.NextFunction) => {
        try {
            await next();
            ctx.set("x-content-type-options", "nosniff");
            ctx.set("docker-distribution-api-version", "registry/2.0");
        } catch (error) {
            if (error instanceof AuthenticationError) {
                const errorMessage: DockerErrorSchema = {
                    errors: [
                        {
                            code: "UNAUTHORIZED",
                            detail: process.env.NODE_ENV === "development" ? error.stack : "",
                            message: error.message
                        }
                    ]
                };

                ctx.response.status = 401;

                if (config.localAuthentication.type === "basic") {
                    ctx.set("www-authenticate", `basic realm="${config.realm}"`);
                }
                if (config.localAuthentication.type === "oauth") {
                    ctx.set(
                        "www-authenticate",
                        createOauthWwwAuthenticateFromConfig(config.localAuthentication));
                }

                ctx.response.body = errorMessage;
            }
            else if (error instanceof DigestInvalidError) {
                const errorMessage: DockerErrorSchema = {
                    errors: [
                        {
                            code: "DIGEST_INVALID",
                            detail: process.env.NODE_ENV === "development" ? error.stack : "",
                            message: error.message
                        }
                    ]
                };

                ctx.response.status = 400;
                ctx.response.body = errorMessage;
            }
            else if (error instanceof RepositoryNameInvalidError) {
                const errorMessage: DockerErrorSchema = {
                    errors: [
                        {
                            code: "NAME_INVALID",
                            detail: process.env.NODE_ENV === "development" ? error.stack : "",
                            message: error.message
                        }
                    ]
                };

                ctx.response.status = 400;
                ctx.response.body = errorMessage;
            }
            else if (error instanceof RepositoryNotFoundError) {
                const errorMessage: DockerErrorSchema = {
                    errors: [
                        {
                            code: "NAME_UNKNOWN",
                            detail: process.env.NODE_ENV === "development" ? error.stack : "",
                            message: error.message
                        }
                    ]
                };

                ctx.response.status = 400;
                ctx.response.body = errorMessage;
            }
            else if (error instanceof ManifestUnknownError) {
                const errorMessage: DockerErrorSchema = {
                    errors: [
                        {
                            code: "MANIFEST_UNKNOWN",
                            detail: process.env.NODE_ENV === "development" ? error.stack : "",
                            message: error.message
                        }
                    ]
                };

                ctx.response.status = 404;
                ctx.response.body = errorMessage;
            }
            else if (error instanceof TagInvalidError) {
                const errorMessage: DockerErrorSchema = {
                    errors: [
                        {
                            code: "TAG_INVALID",
                            detail: process.env.NODE_ENV === "development" ? error.stack : "",
                            message: error.message
                        }
                    ]
                };

                ctx.response.status = 400;
                ctx.response.body = errorMessage;
            }
            else {
                ctx.response.status = 500;
            }
        }
    });

    if (config.localAuthentication.type === "basic") {
        const localAuth = { ...config.localAuthentication };
        router.use("/v2/", async (ctx, next) => {
            const user = basicAuth(ctx.req);
            if (user) {
                const scope = await localAuth.authenticate(user.name, user.pass);
                if (scope) {

                    ctx.state = {
                        allowedRepos: new Set(scope),
                        username: user.name
                    };

                    await next();

                    return;
                }
            }

            throw new AuthenticationError("Authentication failed!");
        });
    }
    else if (config.localAuthentication.type === "oauth") {
        const localAuth = { ...config.localAuthentication };
        validateLocalAuthenticationOAuth(localAuth);

        router.post("/token", bodyParser({ urlencoded: true }), async (ctx) => {
            if (ctx.request.headers["content-type"]?.toLocaleLowerCase() !== "application/x-www-form-urlencoded") {
                throw new AuthenticationError("Content type for token request not supported!");
            }

            const tokenRequest: DockerOAuth2TokenRequest = ctx.request.body;
            validateOAuth2TokenRequest(tokenRequest, localAuth);

            let username: string;
            let refreshToken: string | undefined = undefined;

            if (tokenRequest.grant_type === "password") {
                validateTokenRequestPassword(tokenRequest);

                // password and username are defined if validation didnt throw
                const successfullyAuthenticated = await localAuth.authenticate(tokenRequest.username!, tokenRequest.password!);
                if (!successfullyAuthenticated) {
                    throw new AuthenticationError("Authentication failed!");
                }

                username = tokenRequest.username!;

                if (tokenRequest.access_type === "offline") {
                    refreshToken = createTokenWithData({
                        un: username,
                        t: "r"
                    }, localAuth.jwtSecret, undefined)
                }
            }
            else if (tokenRequest.grant_type === "refresh_token") {
                validateTokenRequestRefreshToken(tokenRequest);

                const refreshTokenData = extractDataFromToken(tokenRequest.refresh_token!, localAuth.jwtSecret);
                if (refreshTokenData.t !== "r") {
                    throw new AuthenticationError("Token not valid!");
                }
                
                username = refreshTokenData.un;

                if (tokenRequest.access_type === "offline") {
                    refreshToken = tokenRequest.refresh_token;
                }
            }
            else {
                throw new AuthenticationError("grant_type not supported!");
            }

            const issuedAt = new Date();
            const access_token = createTokenWithData({
                t: "a",
                un: username
            }, localAuth.jwtSecret, localAuth.tokenLifetime);

            ctx.response.body = {
                "access_token": access_token,
                "scope": defaultScope,
                "expires_in": localAuth.tokenLifetime,
                "issued_at": issuedAt.toISOString(),
                "refresh_token": refreshToken
            };
        });

        router.use("/v2/", async (ctx, next) => {
            const authHeader = ctx.request.headers.authorization;
            if (!authHeader) {
                throw new AuthenticationError("Missing authorization header!");
            }
            
            const token = extractTokenFromAuthHeader(Array.isArray(authHeader) ? authHeader : [authHeader]);
            if (!token) {
                throw new AuthenticationError("Bearer token not found!");
            }

            const tokenData = extractDataFromToken(token, localAuth.jwtSecret);
            const repos = await localAuth.resolveRepositories(tokenData.un);

            ctx.state = {
                allowedRepos: new Set(repos),
                username: tokenData.un
            };

            await next();
        });

        router.use("/token", async (ctx, next) => {
            const basicAuthUser = basicAuth(ctx.req);
            if (basicAuthUser) {
                if (await localAuth.authenticate(basicAuthUser.name, basicAuthUser.pass)) {
                    const repos = await localAuth.resolveRepositories(basicAuthUser.name);

                    ctx.state = {
                        allowedRepos: new Set(repos),
                        username: basicAuthUser.name
                    };
        
                    await next();
                    return;
                }
            }

            throw new AuthenticationError("Authentication failed!");
        });

        router.get("/token", async (ctx) => {
            if (!ctx.state.username) { // should never happen
                throw new AuthenticationError("Not authenticated!");
            }

            const q = ctx.request.query;

            const tokenRequest: DockerTokenRequest = {
                client_id: (Array.isArray(q["client_id"]) ? q["client_id"][0] : q["client_id"]) as string,
                scope: (Array.isArray(q["scope"]) ? q["scope"][0] : q["scope"]) as string,
                service: (Array.isArray(q["service"]) ? q["service"][0] : q["service"]) as string,
                offline_token: "true" === String(Array.isArray(q["offline_token"]) ? q["offline_token"][0] : q["offline_token"]).toLowerCase()
            };
            validateTokenRequest(tokenRequest, localAuth);

            let refreshToken : string | undefined = undefined;
            if (tokenRequest.offline_token) {
                refreshToken = createTokenWithData({
                    t: "r",
                    un: ctx.state.username
                }, localAuth.jwtSecret, undefined);
            }

            const issuedAt = new Date();
            const access_token = createTokenWithData({
                t: "a",
                un: ctx.state.username
            }, localAuth.jwtSecret, localAuth.tokenLifetime);

            ctx.response.body = {
                "access_token": access_token,
                "token": access_token, // this might be a problem...
                "expires_in": localAuth.tokenLifetime,
                "issued_at": issuedAt.toISOString(),
                "refresh_token": refreshToken
            };
        });
    }
    else if (config.localAuthentication.type === "none") {
        const localAuth = { ...config.localAuthentication };

        router.use("/v2/", async (ctx, next) => {
            ctx.state = {
                allowedRepos: new Set(localAuth.scope),
            };
            await next();
        });
    }
    else {
        throw new Error("Invalid configuration for localAuthentication!");
    }

    router.get("/v2/", (ctx) => {
        ctx.status = 200;
        ctx.body = "";
    });
    router.get("/v2/_catalog", (ctx) => {
        ctx.body = {
            repositories: Object.keys(ctx.state.allowedRepos)
        };
    });
    router.get("/v2/:repo+/tags/list", async (ctx) => {
        const repoName = ctx.params.repo;
        validateRepositoryName(repoName);

        if (!ctx.state.allowedRepos.has(repoName)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${repoName}/tags/list`, {
            headers: {
                ...(ctx.request.header.accept ? { "accept": ctx.request.header.accept } : {})
            }
        });
        const remoteTagList = await rrResponse.text();
        if (!rrResponse.ok) {
            throw new Error("There was an error fetching from the remote registry!");
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader);
            ctx.set("etag", `"${dockerDigestHeader}"`);
        }
        ctx.response.type = rrResponse.headers.get("content-type") || "application/json";
        ctx.response.body = remoteTagList;
    });


    router.get("/v2/:repo+/blobs/:digest", async (ctx) => {
        validateDigest(ctx.params.digest);
        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${ctx.params.repo}/blobs/${ctx.params.digest}`, {
            headers: {
                ...(ctx.request.header.accept ? { "accept": ctx.request.header.accept } : {})
            }
        })

        ctx.response.type = rrResponse.headers.get("content-type") || "application/octet-stream";
        ctx.response.body = rrResponse.body;
    });
    router.head("/v2/:repo+/blobs/:digest", async (ctx) => {
        validateDigest(ctx.params.digest);
        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${ctx.params.repo}/blobs/${ctx.params.digest}`, {
            method: "head",
            headers: {
                ...(ctx.request.header.accept ? { "accept": ctx.request.header.accept } : {})
            }
        });
        if (!rrResponse.ok) {
            throw new Error("There was an error fetching from the remote registry!");
        }

        const contentLengthHeader = rrResponse.headers.get("content-length");
        if (contentLengthHeader) {
            ctx.set("content-length", contentLengthHeader)
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader);
            ctx.set("etag", `"${dockerDigestHeader}"`);
        }

        ctx.response.type = rrResponse.headers.get("content-type") || "application/octet-stream";
        ctx.response.status = 200;
    });

    router.get("/v2/:repo+/manifests/:reference", async (ctx) => {
        try {
            validateTag(ctx.params.reference);
        } catch {
            validateDigest(ctx.params.reference);
        }

        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${ctx.params.repo}/manifests/${ctx.params.reference}`, {
            headers: {
                ...(ctx.request.header.accept ? { "accept": ctx.request.header.accept } : {})
            }
        });
        const manifest = await rrResponse.text();

        if (!rrResponse.ok) {
            throw new ManifestUnknownError("The manifest was not found!");
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader);
            ctx.set("etag", `"${dockerDigestHeader}"`);
        }

        ctx.response.type = rrResponse.headers.get("content-type") || "application/json";
        ctx.body = manifest;
    });
    router.head("/v2/:repo+/manifests/:reference", async (ctx) => {
        try {
            validateTag(ctx.params.reference);
        } catch {
            validateDigest(ctx.params.reference);
        }

        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${ctx.params.repo}/manifests/${ctx.params.reference}`, {
            method: "head",
            headers: {
                ...(ctx.request.header.accept ? { "accept": ctx.request.header.accept } : {})
            }
        });
        if (!rrResponse.ok) {
            throw new ManifestUnknownError("The manifest was not found!");
        }

        const contentLengthHeader = rrResponse.headers.get("content-length");
        if (contentLengthHeader) {
            ctx.set("content-length", contentLengthHeader)
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader);
            ctx.set("etag", `"${dockerDigestHeader}"`);
        }

        ctx.response.type = rrResponse.headers.get("content-type") || "application/json";
        ctx.response.status = 200;
    });

    return router;
}

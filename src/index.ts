import express from "express";
import validator from "validator";
import basicAuth from "basic-auth";
import fetch from 'cross-fetch';
import urlJoin from 'url-join';
import { AuthenticationError, DigestInvalidError, ManifestUnknownError, RepositoryNameInvalidError, RepositoryNotFoundError } from "./errors";
import Koa from "koa";
import KoaRouter from "@koa/router";

interface RequestContext {
    allowedRepos: Set<string>
}

declare global {
    namespace Express {
        interface Request {
            context: RequestContext
        }
    }
}

interface DockerErrorSchema {
    errors: ({
        code: string,
        message: string,
        detail: any,
    })[]
}

function validateDigest(digest: string) {
    if (!/([A-Fa-f0-9_+.-]+):([A-Fa-f0-9]+)/.test(digest)) {
        throw new DigestInvalidError("The given digest is invalid!");
    }
}
// TODO
function validateTag(tag: string) {
    if (!/([A-Fa-f0-9_+.-]+):([A-Fa-f0-9]+)/.test(tag)) {

    }
    return;
}


function validateRepositoryName(repoName: string) {
    if (repoName.split("/").some(repoNameComponent => !/[a-z0-9]+(?:[._-][a-z0-9]+)*/i.test(repoNameComponent))) {
        throw new RepositoryNameInvalidError("The given repository name is invalid!");
    }
}

export interface ProxyConfig {
    realmName: string,

    privateRegistryUrl: string,
    privateRegistryUsername: string,
    privateRegistryPassword: string,

    authenticate: (username: string, password: string) => Promise<null | undefined | string[]>
}

export function createRouter(config: ProxyConfig) {

    const authReqRR = async (suffix: string, method = "get") => {
        try {
            return await fetch(urlJoin(config.privateRegistryUrl, suffix), {
                method: method,
                headers: {
                    "authorization": `basic ${Buffer.from(
                        config.privateRegistryUsername +
                        ':' +
                        config.privateRegistryPassword).toString('base64')}`
                }
            });
        } catch {
            throw new Error("Failed requesting reqource from remote registry!");
        }
    };

    // const authReqRRJson = async (suffix: string) => {
    //     try {
    //         return await fetch(urlJoin(config.privateRegistryUrl, suffix), {
    //             headers: {
    //                 "authorization": `basic ${
    //                     Buffer.from(
    //                         config.privateRegistryUsername + 
    //                         ':' + 
    //                         config.privateRegistryPassword).toString('base64')}`
    //             }
    //         }).then(r => r.json());                
    //     } catch {
    //         throw new Error("Failed requesting reqource from remote registry!");
    //     }
    // };

    const router = new KoaRouter<RequestContext>();

    router.use("/v2/", async (ctx, next: express.NextFunction) => {
        try {
            console.log("accessing: ", ctx.path);
            await next();
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

                ctx.response.status = 403;
                ctx.set("WWW-Authenticate", `Basic realm=${config.realmName}`);
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
            else {
                console.log("an error occured: ", error);
                ctx.response.status = 500;
            }
        }
    });

    router.use("/v2/", async (ctx, next) => {
        const user = basicAuth(ctx.req);

        // if (user) {
            const scope = await config.authenticate(user?.name || "", user?.pass || "");

            if (scope) {

                ctx.state = {
                    allowedRepos: new Set(scope)
                };

                await next();

                return;
            }
        // }

        if (!user) {
            throw new AuthenticationError("Authentication failed!");
        }
    });

    router.get("/v2/", (ctx) => ctx.status = 200);
    router.get("/v2/_catalog", (ctx) => {
        ctx.body = {
            repositories: Object.keys(ctx.state.allowedRepos)
        };
    });
    router.get("/v2/:repo*/tags/list", async (ctx) => {
        const repoName = ctx.params.repo;
        validateRepositoryName(repoName);

        if (!ctx.state.allowedRepos.has(repoName)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${repoName}/tags/list`);
        const remoteTagList = await rrResponse.json();
        if ("errors" in remoteTagList || !remoteTagList.tags || !remoteTagList.name || !rrResponse.ok) {
            throw new Error("There was an error fetching from the remote registry!");
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader)
        }
        ctx.response.body = remoteTagList;
    });


    router.get("/v2/:repo*/blobs/:digest", async (ctx) => {
        validateDigest(ctx.params.digest);
        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const result = await authReqRR(`/v2/${ctx.params.repo}/blobs/${ctx.params.digest}`)
        ctx.response.body = result.body;
    });
    router.head("/v2/:repo*/blobs/:digest", async (ctx) => {
        validateDigest(ctx.params.digest);
        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${ctx.params.repo}/blobs/${ctx.params.digest}`, "head");
        if (!rrResponse.ok) {
            throw new Error("There was an error fetching from the remote registry!");
        }

        const contentLengthHeader = rrResponse.headers.get("content-length");
        if (contentLengthHeader) {
            ctx.set("content-length", contentLengthHeader)
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader)
        }

        ctx.response.status = 200;
    });

    router.get("/v2/:repo*/manifests/:reference", async (ctx) => {
        try {
            validateTag(ctx.params.reference);
        } catch {
            validateDigest(ctx.params.reference);
        }

        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${ctx.params.repo}/manifests/${ctx.params.reference}`);
        const manifest = await rrResponse.json();

        if ("errors" in manifest || !rrResponse.ok) {
            throw new ManifestUnknownError("The manifest was not found!");
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader)
        }

        ctx.body = manifest;
    });
    router.head("/v2/:repo*/manifests/:reference", async (ctx) => {
        try {
            validateTag(ctx.params.reference);
        } catch {
            validateDigest(ctx.params.reference);
        }

        validateRepositoryName(ctx.params.repo);

        if (!ctx.state.allowedRepos.has(ctx.params.repo)) {
            throw new RepositoryNotFoundError("The requested repository was not found!");
        }

        const rrResponse = await authReqRR(`/v2/${ctx.params.repo}/manifests/${ctx.params.reference}`, "head");
        if (!rrResponse.ok) {
            throw new ManifestUnknownError("The manifest was not found!");
        }

        const contentLengthHeader = rrResponse.headers.get("content-length");
        if (contentLengthHeader) {
            ctx.set("content-length", contentLengthHeader)
        }

        const dockerDigestHeader = rrResponse.headers.get("docker-content-digest");
        if (dockerDigestHeader) {
            ctx.set("docker-content-digest", dockerDigestHeader)
        }

        ctx.response.status = 200;
    });

    return router;
}

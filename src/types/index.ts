export * from "./config";

export interface DockerErrorSchema {
    errors: ({
        code: string,
        message: string,
        detail: any,
    })[]
}

export interface RequestContext {
    allowedRepos: Set<string>
}

export class AuthenticationError extends Error {
    constructor(msg: string) {
        super(msg);
        Object.setPrototypeOf(this, AuthenticationError.prototype);
    }
}

export class RepositoryNameInvalidError extends Error {
    constructor(msg: string) {
        super(msg);
        Object.setPrototypeOf(this, RepositoryNameInvalidError.prototype);
    }
}

export class RepositoryNotFoundError extends Error {
    constructor(msg: string) {
        super(msg);
        Object.setPrototypeOf(this, RepositoryNotFoundError.prototype);
    }
}

export class DigestInvalidError extends Error {
    constructor(msg: string) {
        super(msg);
        Object.setPrototypeOf(this, DigestInvalidError.prototype);
    }
}

export class TagInvalidError extends Error {
    constructor(msg: string) {
        super(msg);
        Object.setPrototypeOf(this, TagInvalidError.prototype);
    }
}

export class ManifestUnknownError extends Error {
    constructor(msg: string) {
        super(msg);
        Object.setPrototypeOf(this, ManifestUnknownError.prototype);
    }
}

import { DigestInvalidError, RepositoryNameInvalidError, TagInvalidError } from "../errors";

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

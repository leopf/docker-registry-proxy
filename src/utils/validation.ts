import { DigestInvalidError, RepositoryNameInvalidError } from "../errors";

export function validateDigest(digest: string) {
    if (!/([A-Fa-f0-9_+.-]+):([A-Fa-f0-9]+)/.test(digest)) {
        throw new DigestInvalidError("The given digest is invalid!");
    }
}
// TODO
export function validateTag(tag: string) {
    if (!/([A-Fa-f0-9_+.-]+):([A-Fa-f0-9]+)/.test(tag)) {

    }
    return;
}

export function validateRepositoryName(repoName: string) {
    if (repoName.split("/").some(repoNameComponent => !/[a-z0-9]+(?:[._-][a-z0-9]+)*/i.test(repoNameComponent))) {
        throw new RepositoryNameInvalidError("The given repository name is invalid!");
    }
}

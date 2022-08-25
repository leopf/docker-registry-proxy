export function createBasicAuthHeaderValue(username: string, password: string) {
    return `basic ${Buffer.from(
        username +
        ':' +
        password).toString('base64')}`;
}
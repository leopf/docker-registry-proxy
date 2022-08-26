export function createBasicAuthHeaderValue(username: string, password: string) {
    if (username.includes(":") || password.includes(":")) {
        throw new Error("username and password cannot contain a colon!");
    }

    return `basic ${Buffer.from(
        username +
        ':' +
        password).toString('base64')}`;
}
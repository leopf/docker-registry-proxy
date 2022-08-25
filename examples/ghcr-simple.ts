import Koa from "koa";
import { createRouter } from "../src";

const app = new Koa();

const router = createRouter({
    remoteRegistryUrl: "https://ghcr.io",
    localAuthentication: {
        type: "basic",
        authenticate: async (username, password) => {
            if (username === "test" && password === "1234") {
                return [`${process.env["GITHUB_USER"]}/my-ubuntu`];
            }
            return undefined;
        }
    },
    remoteAuthentication: {
        type: "oauth2",
        username: process.env["GITHUB_USER"] as string,
        password: process.env["GITHUB_TOKEN"] as string,
    },
    realm: "Registry",
});

app.use(router.routes());

app.listen(5001, undefined, undefined, () => console.log("listening on port 5001"));
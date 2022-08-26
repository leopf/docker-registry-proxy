import Koa from "koa";
import { createRouter } from "../src";

const app = new Koa();

const router = createRouter({
    remoteRegistryUrl: "http://localhost:5000",
    localAuthentication: {
        type: "oauth",
        resolveRepositories: async () => [ "my-ubuntu" ],
        authenticate: async (username, password) => {
            if (username === "test" && password === "1234") {
                return true;
            }   
            return false;
        },
        jwtSecret: "password", // Set this to a secure value
        service: "localhost:5001",
        tokenLifetime: 900,
    },
    realm: "Registry",
});

app.use(router.routes());

app.listen(5001, undefined, undefined, () => console.log("listening on port 5001"));
import Koa from "koa";
import { createRouter } from "../src";

const app = new Koa();

const router = createRouter({
    remoteRegistryUrl: "http://localhost:5000",
    localAuthentication: {
        type: "basic",
        authenticate: async (username, password) => {
            if (username === "test" && password === "1234") {
                return [ "my-ubuntu" ];
            }   
            return undefined;
        }
    },
    realm: "Registry",
});

app.use(router.routes());

app.listen(5001, undefined, undefined, () => console.log("listening on port 5001"));
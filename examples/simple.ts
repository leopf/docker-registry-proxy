import Koa from "koa";
import { createRouter } from "../src";

const app = new Koa();

const router = createRouter({
    remoteRegistryUrl: "http://localhost:5000",
    localAuthentication: {
        type: "none",
        scope: [ "my-ubuntu/test" ]
    },
    realmName: "registry",
});

app.use(router.routes());

app.listen(5001, undefined, undefined, () => console.log("listening on port 5001"));
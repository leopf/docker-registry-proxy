import Koa from "koa";
import { createRouter } from "../src";

const app = new Koa();

const router = createRouter({
    remoteRegistryUrl: "http://localhost:5000",
    privateRegistryPassword: "1234",
    privateRegistryUsername: "test",
    realmName: "registry",
    authenticate: async () => [ "my-ubuntu/test" ]
});

app.use(router.routes());

app.listen(5001, undefined, undefined, () => console.log("listening on port 5001"));
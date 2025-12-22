import "dotenv/config";
import { createApp } from "./app";

const port = Number(process.env.PORT || 3001);
const app = createApp();

app.listen(port, () => {
    process.stdout.write(`listening on ${port}\n`);
});
/* Worker entry exporting the controller DO for workerd-based tests. */
export { DatabaseControllerDO } from "./database-controller.ts";

export default {
  async fetch(): Promise<Response> {
    return new Response("controller worker", { status: 200 });
  },
};

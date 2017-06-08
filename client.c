// pseudocode:
/*

injector_get_any_connection()
{
    injector_connection = pop(_idle_injector_connections);
    if (injector_connection) {
        return injector_connection;
    }
    injectors = dht_get_peers(injector_swarm);
    injector_proxies = dht_get_peers(injector_proxy_swarm);
    injector_connection = utp_connect_to_one(shuffle(injectors) + shuffle(injector_proxies));
    return injector_connection;
}

handle_connection(socket_t s)
{
    for (;;) {
        req = http_read_request(s);
        content_hash = dht_get(hash(req->url));
        // these can happen in parallel, but only one http_response should be returned
        if (!content_hash) {
            injector = injector_get_any_connection();
            data = request(injector, req->url);
            http_respond(s, data);
        } else {
            swarm_hash = dht_get(content_hash);
            if (swarm_hash) {
                data = swarm(swarm_hash);
                http_respond(s, data);
            }
        }
    }
}

*/

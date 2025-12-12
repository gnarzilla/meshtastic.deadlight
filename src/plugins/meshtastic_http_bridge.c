// src/plugins/meshtastic_http_bridge.c
#include "meshtastic_http_bridge.h"
#include "meshtastic_framing.h"
#include <gio/gio.h>
#include <string.h>

static void destroy_byte_array(gpointer p) {
    if (p) g_byte_array_free((GByteArray *)p, TRUE);
}

// Local helper: send an error response and indicate the plugin handled it.
static gboolean write_simple_response(DeadlightConnection *conn, int status, const char *msg) {
    if (!conn || !conn->client_connection) return TRUE;
    GOutputStream *os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    gchar *body = g_strdup_printf("%d %s\n", status, msg ? msg : "");
    gchar *resp = g_strdup_printf(
        "HTTP/1.1 %d %s\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %u\r\n"
        "\r\n"
        "%s",
        status, msg ? msg : "Error",
        (unsigned)strlen(body),
        body
    );
    g_output_stream_write_all(os, resp, strlen(resp), NULL, NULL, NULL);
    g_free(body);
    g_free(resp);
    return TRUE;
}

static guint64 next_session(MeshtasticData *data, guint64 conn_id) {
    // session_id = (conn_id << 32) | counter
    guint64 counter = (guint64)(data->next_session_id++ & 0xFFFFFFFFu);
    return (conn_id << 32) | counter;
}

static gboolean ensure_connection_close_header(GByteArray *req) {
    // Simple, byte-level header tweak: ensure "Connection: close".
    // If already present, we do nothing (minimal risk).
    const gchar *needle = "\r\nConnection:";
    if (g_strstr_len((const gchar*)req->data, req->len, needle)) {
        return TRUE;
    }
    const gchar *headers_end = g_strstr_len((const gchar*)req->data, req->len, "\r\n\r\n");
    if (!headers_end) return FALSE;
    gsize off = (gsize)(headers_end - (const gchar*)req->data);
    const gchar *insert = "\r\nConnection: close";
    g_byte_array_insert(req, off, (const guint8*)insert, strlen(insert));
    return TRUE;
}

static gboolean parse_content_length(const guint8 *data, gsize len, guint64 *out_len) {
    const gchar *cl = "\r\nContent-Length:";
    const gchar *p = g_strstr_len((const gchar*)data, len, cl);
    if (!p) return FALSE;
    p += strlen(cl);
    while ((p < (const gchar*)data + len) && (*p == ' ' || *p == '\t')) p++;
    gchar *endp = NULL;
    guint64 v = g_ascii_strtoull(p, &endp, 10);
    if (endp == p) return FALSE;
    *out_len = v;
    return TRUE;
}

static GByteArray *read_full_http_request(DeadlightConnection *conn) {
    // Start from whatever bytes we already have in client_buffer (peeked during detection).
    GByteArray *req = g_byte_array_new();
    if (conn->client_buffer && conn->client_buffer->len) {
        g_byte_array_append(req, conn->client_buffer->data, conn->client_buffer->len);
    }

    // Wait for complete headers
    GInputStream *is = g_io_stream_get_input_stream(G_IO_STREAM(conn->client_connection));
    guint8 tmp[4096];
    while (!g_strstr_len((const gchar*)req->data, req->len, "\r\n\r\n")) {
        gssize n = g_input_stream_read(is, tmp, sizeof(tmp), NULL, NULL);
        if (n <= 0) break;
        g_byte_array_append(req, tmp, (gsize)n);
        if (req->len > (1024 * 1024)) break; // 1MB hard cap
    }

    const gchar *headers_end = g_strstr_len((const gchar*)req->data, req->len, "\r\n\r\n");
    if (!headers_end) return req;

    gsize header_total = (gsize)((headers_end - (const gchar*)req->data) + 4);
    guint64 content_len = 0;
    if (parse_content_length(req->data, header_total, &content_len)) {
        guint64 already = req->len > header_total ? (req->len - header_total) : 0;
        while (already < content_len) {
            gssize n = g_input_stream_read(is, tmp, sizeof(tmp), NULL, NULL);
            if (n <= 0) break;
            g_byte_array_append(req, tmp, (gsize)n);
            already += (guint64)n;
            if (req->len > (4 * 1024 * 1024)) break; // 4MB hard cap for now
        }
    }

    return req;
}

static gboolean send_over_mesh(MeshtasticData *data,
                               guint32 to_node_id,
                               guint64 session_id,
                               MeshtasticDirection dir,
                               const guint8 *bytes,
                               gsize len) {
    if (!data || !data->serial_channel || data->chunk_data_max == 0) return FALSE;
    guint32 total = (guint32)((len + data->chunk_data_max - 1) / data->chunk_data_max);
    if (total == 0) total = 1;

    for (guint32 i = 0; i < total; i++) {
        gsize off = (gsize)i * data->chunk_data_max;
        gsize clen = MIN((gsize)data->chunk_data_max, len - off);
        // Build on-wire payload
        GByteArray *wire = meshtastic_transport_build_chunk(session_id, dir, i, total, bytes + off, (guint16)clen);

        meshtastic_Data pb_data = meshtastic_Data_init_default;
        pb_data.portnum = (meshtastic_PortNum)data->custom_port;
        if (wire->len > sizeof(pb_data.payload.bytes)) {
            g_byte_array_free(wire, TRUE);
            return FALSE;
        }
        pb_data.payload.size = (pb_size_t)wire->len;
        memcpy(pb_data.payload.bytes, wire->data, wire->len);
        g_byte_array_free(wire, TRUE);

        meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_default;
        packet.decoded = pb_data;
        packet.channel = (uint32_t)data->channel_index;
        packet.to = to_node_id;

        uint8_t packet_buf[512];
        pb_ostream_t ostream = pb_ostream_from_buffer(packet_buf, sizeof(packet_buf));
        if (!pb_encode(&ostream, meshtastic_MeshPacket_fields, &packet)) {
            return FALSE;
        }

        meshtastic_ToRadio to_radio = meshtastic_ToRadio_init_default;
        to_radio.which_payload_variant = meshtastic_ToRadio_packet_tag;
        to_radio.packet = packet;

        uint8_t to_buf[512];
        pb_ostream_t to_ostream = pb_ostream_from_buffer(to_buf, sizeof(to_buf));
        if (!pb_encode(&to_ostream, meshtastic_ToRadio_fields, &to_radio)) {
            return FALSE;
        }

        g_mutex_lock(&data->mutex);
        GError *err = NULL;
        gboolean ok = meshtastic_framing_write_delimited(data->serial_channel, to_buf, to_ostream.bytes_written, &err);
        g_mutex_unlock(&data->mutex);
        if (!ok) {
            if (err) g_error_free(err);
            return FALSE;
        }
    }
    return TRUE;
}

gboolean meshtastic_client_forward_http(MeshtasticData *data, DeadlightRequest *request) {
    if (!data || !request || !request->connection) return FALSE;
    if (!data->enabled || data->mode != MESHTASTIC_MODE_CLIENT) return FALSE;
    if (data->gateway_node_id == 0) {
        // Misconfigured; fall back to normal proxy behavior
        return FALSE;
    }
    if (request->method && g_ascii_strcasecmp(request->method, "CONNECT") == 0) {
        // Not supported over mesh in this PR
        return FALSE;
    }

    DeadlightConnection *conn = request->connection;
    GByteArray *req_bytes = read_full_http_request(conn);
    if (!req_bytes || req_bytes->len == 0) {
        if (req_bytes) g_byte_array_free(req_bytes, TRUE);
        return write_simple_response(conn, 400, "Bad Request");
    }

    (void)ensure_connection_close_header(req_bytes);

    // Create a per-request response queue
    GAsyncQueue *q = g_async_queue_new_full(destroy_byte_array);
    guint64 session_id = next_session(data, conn->id);

    g_mutex_lock(&data->pending_mutex);
    {
        guint64 *key = g_new(guint64, 1);
        *key = session_id;
        g_hash_table_insert(data->pending, key, g_async_queue_ref(q));
    }
    g_mutex_unlock(&data->pending_mutex);

    // Send request over mesh
    gboolean sent = send_over_mesh(data,
                                   data->gateway_node_id,
                                   session_id,
                                   MESHTASTIC_DIR_REQUEST,
                                   req_bytes->data,
                                   req_bytes->len);
    g_byte_array_free(req_bytes, TRUE);

    if (!sent) {
        // cleanup mapping
        g_mutex_lock(&data->pending_mutex);
        g_hash_table_remove(data->pending, &session_id);
        g_mutex_unlock(&data->pending_mutex);
        g_async_queue_unref(q);
        return write_simple_response(conn, 502, "Mesh send failed");
    }

    // Wait for response (120s)
    gpointer got = g_async_queue_timeout_pop(q, 120 * G_USEC_PER_SEC);
    g_async_queue_unref(q);

    // Always remove mapping
    g_mutex_lock(&data->pending_mutex);
    g_hash_table_remove(data->pending, &session_id);
    g_mutex_unlock(&data->pending_mutex);

    if (!got) {
        return write_simple_response(conn, 504, "Gateway timeout");
    }

    GByteArray *resp_bytes = (GByteArray *)got;
    GOutputStream *os = g_io_stream_get_output_stream(G_IO_STREAM(conn->client_connection));
    g_output_stream_write_all(os, resp_bytes->data, resp_bytes->len, NULL, NULL, NULL);
    g_byte_array_free(resp_bytes, TRUE);
    return TRUE;
}

void meshtastic_gateway_handle_http_request(MeshtasticData *data,
                                            guint32 from_node_id,
                                            guint64 session_id,
                                            GByteArray *request_bytes) {
    if (!data || !request_bytes) return;

    // Very small proxy: parse Host header and connect; always close.
    gchar *host = NULL;
    guint16 port = 80;
    const gchar *host_hdr = g_strstr_len((const gchar*)request_bytes->data, request_bytes->len, "\r\nHost:");
    if (!host_hdr) host_hdr = g_strstr_len((const gchar*)request_bytes->data, request_bytes->len, "\r\nhost:");
    if (host_hdr) {
        host_hdr += strlen("\r\nHost:");
        while (*host_hdr == ' ' || *host_hdr == '\t') host_hdr++;
        const gchar *eol = strstr(host_hdr, "\r\n");
        if (eol) {
            gchar *hp = g_strndup(host_hdr, eol - host_hdr);
            // split host:port
            gchar **parts = g_strsplit(hp, ":", 2);
            host = g_strdup(parts[0]);
            if (parts[1]) port = (guint16)atoi(parts[1]);
            g_strfreev(parts);
            g_free(hp);
        }
    }

    if (!host) {
        // Return 400 over mesh
        const gchar *resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        send_over_mesh(data, from_node_id, session_id, MESHTASTIC_DIR_RESPONSE, (const guint8*)resp, strlen(resp));
        return;
    }

    // Force Connection: close to simplify response reading
    ensure_connection_close_header(request_bytes);

    GError *err = NULL;
    GSocketClient *client = g_socket_client_new();
    g_socket_client_set_timeout(client, 30);
    GSocketConnection *up = g_socket_client_connect_to_host(client, host, port, NULL, &err);
    g_object_unref(client);

    if (!up) {
        const gchar *resp = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        send_over_mesh(data, from_node_id, session_id, MESHTASTIC_DIR_RESPONSE, (const guint8*)resp, strlen(resp));
        if (err) g_error_free(err);
        g_free(host);
        return;
    }

    GOutputStream *uos = g_io_stream_get_output_stream(G_IO_STREAM(up));
    g_output_stream_write_all(uos, request_bytes->data, request_bytes->len, NULL, NULL, NULL);

    // Read until EOF (since we force close)
    GInputStream *uis = g_io_stream_get_input_stream(G_IO_STREAM(up));
    GByteArray *resp_bytes = g_byte_array_new();
    guint8 buf[4096];
    for (;;) {
        gssize n = g_input_stream_read(uis, buf, sizeof(buf), NULL, NULL);
        if (n <= 0) break;
        g_byte_array_append(resp_bytes, buf, (gsize)n);
        if (resp_bytes->len > (4 * 1024 * 1024)) break; // 4MB cap
    }

    g_io_stream_close(G_IO_STREAM(up), NULL, NULL);
    g_object_unref(up);
    g_free(host);

    send_over_mesh(data, from_node_id, session_id, MESHTASTIC_DIR_RESPONSE, resp_bytes->data, resp_bytes->len);
    g_byte_array_free(resp_bytes, TRUE);
}



#include <Network/Network.h>
#include <dispatch/dispatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    TINY_NETWORK_OK = 0,
    TINY_NETWORK_INVALID_ARGUMENT = 1,
    TINY_NETWORK_ALLOCATION_FAILED = 2,
    TINY_NETWORK_CONNECTION_FAILED = 3,
    TINY_NETWORK_TIMEOUT = 4,
    TINY_NETWORK_SEND_FAILED = 5,
    TINY_NETWORK_RECEIVE_FAILED = 6,
};

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
    int error;
    bool ready;
    bool complete;
    dispatch_semaphore_t semaphore;
    nw_connection_t connection;
} tiny_state_t;

static bool tiny_append(tiny_state_t *state, const uint8_t *data, size_t len) {
    if (len == 0) {
        return true;
    }

    if (state->len > SIZE_MAX - len) {
        return false;
    }

    size_t required = state->len + len;
    if (required > state->capacity) {
        size_t capacity = state->capacity ? state->capacity : 8192;

        while (capacity < required) {
            if (capacity > SIZE_MAX / 2) {
                capacity = required;
                break;
            }
            capacity *= 2;
        }

        uint8_t *new_data = realloc(state->data, capacity);
        if (!new_data) {
            return false;
        }

        state->data = new_data;
        state->capacity = capacity;
    }

    memcpy(state->data + state->len, data, len);
    state->len += len;
    return true;
}

static void tiny_receive(tiny_state_t *state);

static void tiny_state_changed(
    nw_connection_t connection,
    nw_connection_state_t state_value,
    nw_error_t error,
    void *context
) {
    tiny_state_t *state = context;

    switch (state_value) {
        case nw_connection_state_ready:
            state->ready = true;
            dispatch_semaphore_signal(state->semaphore);
            break;

        case nw_connection_state_failed:
            (void)error;
            if (state->error == TINY_NETWORK_OK) {
                state->error = TINY_NETWORK_CONNECTION_FAILED;
            }
            dispatch_semaphore_signal(state->semaphore);
            break;

        case nw_connection_state_cancelled:
            if (!state->complete && state->error == TINY_NETWORK_OK) {
                state->error = TINY_NETWORK_CONNECTION_FAILED;
            }
            dispatch_semaphore_signal(state->semaphore);
            break;

        default:
            break;
    }

    (void)connection;
}

static void tiny_send_complete(
    nw_error_t error,
    void *context
) {
    tiny_state_t *state = context;

    if (error != NULL) {
        state->error = TINY_NETWORK_SEND_FAILED;
        dispatch_semaphore_signal(state->semaphore);
        return;
    }

    tiny_receive(state);
}

static void tiny_receive(
    tiny_state_t *state
) {
    nw_connection_receive(
        state->connection,
        1,
        64 * 1024,
        ^(dispatch_data_t content,
          nw_content_context_t context,
          bool is_complete,
          nw_error_t error) {
            (void)context;

            if (error != NULL) {
                state->error = TINY_NETWORK_RECEIVE_FAILED;
                dispatch_semaphore_signal(state->semaphore);
                return;
            }

            if (content != NULL) {
                bool ok = dispatch_data_apply(
                    content,
                    ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                        (void)region;
                        (void)offset;
                        return tiny_append(state, buffer, size);
                    }
                );

                if (!ok) {
                    state->error = TINY_NETWORK_ALLOCATION_FAILED;
                    dispatch_semaphore_signal(state->semaphore);
                    return;
                }
            }

            if (is_complete) {
                state->complete = true;
                dispatch_semaphore_signal(state->semaphore);
                return;
            }

            tiny_receive(state);
        }
    );
}

int tiny_network_https_get(
    const char *host,
    size_t host_len,
    uint16_t port,
    const uint8_t *request,
    size_t request_len,
    uint8_t **response,
    size_t *response_len,
    uint32_t timeout_seconds
) {
    if (!host || host_len == 0 || !request || request_len == 0 || !response || !response_len) {
        return TINY_NETWORK_INVALID_ARGUMENT;
    }

    *response = NULL;
    *response_len = 0;

    char port_string[6];
    int port_length = snprintf(port_string, sizeof(port_string), "%u", (unsigned)port);
    if (port_length <= 0 || (size_t)port_length >= sizeof(port_string)) {
        return TINY_NETWORK_INVALID_ARGUMENT;
    }

    char *host_string = malloc(host_len + 1);
    if (!host_string) {
        return TINY_NETWORK_ALLOCATION_FAILED;
    }

    memcpy(host_string, host, host_len);
    host_string[host_len] = '\0';

    nw_endpoint_t endpoint = nw_endpoint_create_host(host_string, port_string);
    free(host_string);

    if (!endpoint) {
        return TINY_NETWORK_CONNECTION_FAILED;
    }

    nw_parameters_t parameters = nw_parameters_create_secure_tcp(
        NW_PARAMETERS_DEFAULT_CONFIGURATION,
        NW_PARAMETERS_DEFAULT_CONFIGURATION
    );
    if (!parameters) {
        nw_release(endpoint);
        return TINY_NETWORK_CONNECTION_FAILED;
    }

    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    nw_release(parameters);
    nw_release(endpoint);

    if (!connection) {
        return TINY_NETWORK_CONNECTION_FAILED;
    }

    tiny_state_t state = {
        .data = NULL,
        .len = 0,
        .capacity = 0,
        .error = TINY_NETWORK_OK,
        .ready = false,
        .complete = false,
        .semaphore = dispatch_semaphore_create(0),
        .connection = connection,
    };

    if (!state.semaphore) {
        nw_release(connection);
        return TINY_NETWORK_CONNECTION_FAILED;
    }

    nw_connection_set_queue(connection, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0));
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t connection_state, nw_error_t error) {
        tiny_state_changed(connection, connection_state, error, &state);
    });

    nw_connection_start(connection);

    dispatch_time_t timeout = dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)timeout_seconds * NSEC_PER_SEC
    );

    if (dispatch_semaphore_wait(state.semaphore, timeout) != 0) {
        state.error = TINY_NETWORK_TIMEOUT;
        nw_connection_cancel(connection);
        dispatch_semaphore_wait(state.semaphore, DISPATCH_TIME_FOREVER);
        free(state.data);
        nw_release(connection);
        dispatch_release(state.semaphore);
        return TINY_NETWORK_TIMEOUT;
    }

    if (!state.ready || state.error != TINY_NETWORK_OK) {
        int error = state.error ? state.error : TINY_NETWORK_CONNECTION_FAILED;
        nw_connection_cancel(connection);
        dispatch_semaphore_wait(state.semaphore, DISPATCH_TIME_FOREVER);
        free(state.data);
        nw_release(connection);
        dispatch_release(state.semaphore);
        return error;
    }

    uint8_t *request_copy = malloc(request_len);
    if (!request_copy) {
        nw_connection_cancel(connection);
        dispatch_semaphore_wait(state.semaphore, DISPATCH_TIME_FOREVER);
        free(state.data);
        nw_release(connection);
        dispatch_release(state.semaphore);
        return TINY_NETWORK_ALLOCATION_FAILED;
    }

    memcpy(request_copy, request, request_len);

    dispatch_data_t request_data = dispatch_data_create(
        request_copy,
        request_len,
        dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
        DISPATCH_DATA_DESTRUCTOR_DEFAULT
    );

    if (!request_data) {
        free(request_copy);
        nw_connection_cancel(connection);
        dispatch_semaphore_wait(state.semaphore, DISPATCH_TIME_FOREVER);
        free(state.data);
        nw_release(connection);
        dispatch_release(state.semaphore);
        return TINY_NETWORK_ALLOCATION_FAILED;
    }

    nw_connection_send(
        connection,
        request_data,
        NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
        true,
        ^(nw_error_t error) {
            tiny_send_complete(error, &state);
        }
    );

    dispatch_release(request_data);

    if (dispatch_semaphore_wait(state.semaphore, timeout) != 0) {
        state.error = TINY_NETWORK_TIMEOUT;
        nw_connection_cancel(connection);
        dispatch_semaphore_wait(state.semaphore, DISPATCH_TIME_FOREVER);
        free(state.data);
        nw_release(connection);
        dispatch_release(state.semaphore);
        return TINY_NETWORK_TIMEOUT;
    }

    if (state.error != TINY_NETWORK_OK || !state.complete) {
        int error = state.error ? state.error : TINY_NETWORK_RECEIVE_FAILED;
        nw_connection_cancel(connection);
        dispatch_semaphore_wait(state.semaphore, DISPATCH_TIME_FOREVER);
        free(state.data);
        nw_release(connection);
        dispatch_release(state.semaphore);
        return error;
    }

    nw_connection_cancel(connection);
    dispatch_semaphore_wait(state.semaphore, DISPATCH_TIME_FOREVER);
    nw_release(connection);
    dispatch_release(state.semaphore);

    *response = state.data;
    *response_len = state.len;

    return TINY_NETWORK_OK;
}

void tiny_network_free(void *ptr) {
    free(ptr);
}

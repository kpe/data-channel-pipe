#include <string.h> // memcpy
#include <unistd.h> // STDIN_FILENO, STDOUT_FILENO, close, execvp, read, write
#include <limits.h> // USHRT_MAX
#include <signal.h> // SIGTERM, kill
#include <stdlib.h> // setenv
#include <termios.h> // ioctl, struct winsize
#include <stropts.h> // ioctl I_NREAD

#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"
#include "helper/parameters.h"

#define DEBUG_MODULE "rawrtc-terminal"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

enum {
    PIPE_READ_BUFFER = 4096
};

// Control message types
enum {
    CONTROL_MESSAGE_WINDOW_SIZE_TYPE = 0
};

// Control message lengths
enum {
    CONTROL_MESSAGE_WINDOW_SIZE_LENGTH = 5
};

static char const ws_uri_regex[] = "ws:[^]*";

struct parameters {
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_ice_candidates* ice_candidates;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct sctp_parameters sctp_parameters;
};

// Note: Shadows struct client
struct terminal_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    char* ws_uri;
    struct rawrtc_ice_gather_options* gather_options;
    enum rawrtc_ice_role role;
    struct dnsc* dns_client;
    struct http_cli* http_client;
    struct websock* ws_socket;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct rawrtc_data_transport* data_transport;
    struct websock_conn* ws_connection;
    struct list data_channels;
    struct parameters local_parameters;
    struct parameters remote_parameters;
    struct data_channel_helper* data_channel;
};

struct terminal_client_channel {
    pid_t pid;
    int pty;
};

static void client_start_transports(
    struct terminal_client* const client
);

static void client_stop(
    struct terminal_client* const client
);

static void client_apply_parameters(
    struct terminal_client* const client
);

static enum rawrtc_code client_decode_parameters(
    struct parameters* const parametersp,
    struct odict* const dict,
    struct terminal_client* const client
);

static struct odict* client_encode_parameters(
    struct terminal_client* const client
);

static void client_start_gathering(
    struct terminal_client* const client
);



/*
 * Print the WS close event.
 */
static void ws_close_handler(
        int err,
        void* arg
) {
    struct terminal_client* const client = arg;
    DEBUG_PRINTF("(%s) WS connection closed, reason: %m\n", client->name, err);

    if( list_count(&client->data_channels) < 1) {
    	DEBUG_PRINTF("(%s) Can't continue without signaling channel. Exiting...\n");

    	// Stop client & bye
		client_stop(client);
		before_exit();
		exit(0);
    }
}

/*
 * Receive the JSON encoded remote parameters, parse and apply them.
 */
static void ws_receive_handler(
        struct websock_hdr const* header,
        struct mbuf* buffer,
        void* arg
) {
    struct terminal_client* const client = arg;
    enum rawrtc_code error;
    struct odict* dict;
    (void) header;
    DEBUG_PRINTF("(%s) WS message of %zu bytes received\n", client->name, mbuf_get_left(buffer));

    // Check opcode
    if (header->opcode != WEBSOCK_TEXT) {
        DEBUG_NOTICE("(%s) Unexpected opcode (%u) in WS message\n", client->name, header->opcode);
        return;
    }

    if (1 == mbuf_get_left(buffer)) { // receiving role
    	DEBUG_NOTICE("Server assigned role: %c\n", mbuf_buf(buffer)[0]);
    	switch (mbuf_buf(buffer)[0]) {
    	case '0':
    		client->role = RAWRTC_ICE_ROLE_CONTROLLING;
    		break;
    	case '1':
    		client->role = RAWRTC_ICE_ROLE_CONTROLLED;
    		break;
    	}

        // Start gathering
        client_start_gathering(client);

    	return;
    }


    // Decode JSON
    error = rawrtc_error_to_code(json_decode_odict(
            &dict, 16, (char*) mbuf_buf(buffer), mbuf_get_left(buffer), 3));
    if (error) {
        DEBUG_WARNING("(%s) Invalid remote parameters\n", client->name);
        return;
    }

    // Decode parameters
    if (client_decode_parameters(&client->remote_parameters, dict, client) == RAWRTC_CODE_SUCCESS) {
        // Set parameters & start transports
        client_apply_parameters(client);
        client_start_transports(client);

    }

    // Un-reference
    mem_deref(dict);
}

/*
 * Send the JSON encoded local parameters to the other peer.
 */
static void ws_established_handler(
        void* arg
) {
    struct terminal_client* const client = arg;
    DEBUG_PRINTF("(%s) WS connection established\n", client->name);


}

/*
 * Read STDIN and send it to all data channels.
 */
static void stdin_read_handler(
        int flags,
        void* arg
) {
    struct terminal_client* const client = arg;
    enum rawrtc_code error;
    (void) flags;
    int length;
    int i,n;

    // Create buffer
    struct mbuf* const buffer = mbuf_alloc(PIPE_READ_BUFFER);

    struct data_channel_helper* cn_channel;
    struct terminal_client* cn_client;
    struct le *le;

    do {
      // read a line
      DEBUG_PRINTF("Start reading from stdin ...\n");
      if(!fgets((char*)mbuf_buf(buffer), mbuf_get_space(buffer), stdin)) {
        EWE("Error polling stdin");
      }
      length = strnlen(mbuf_buf(buffer), PIPE_READ_BUFFER);
      mbuf_set_end(buffer, (size_t) length);

      mbuf_buf(buffer)[length]='\r';
      mbuf_buf(buffer)[length+1]='\0';
      mbuf_set_end(buffer, (size_t) length+1);

      DEBUG_PRINTF("... DONE reading from stdin: %zu bytes\n", length);

      if(feof(stdin)) {
        DEBUG_NOTICE("stdin EOF reached\n");
        break;
      } else if(ferror(stdin)){
        DEBUG_NOTICE("error reading stdin\n");
        break;
      } else {
        DEBUG_NOTICE("stdin read: %s\n", mbuf_buf(buffer));

        // TODO send through all connected to data channels
        LIST_FOREACH(&client->data_channels, le) {
        	cn_channel = list_ledata(le);
            cn_client = (struct terminal_client* const) cn_channel->client;

            DEBUG_PRINTF("(%s.%s) Sending %zu bytes\n", cn_client->name, cn_channel->label, length);
            EOE(rawrtc_data_channel_send(cn_channel->channel, buffer, false));
        }

        if(ioctl(STDIN_FILENO, I_NREAD, &n) == 0 && n > 0) {
          DEBUG_PRINTF("stdin_read_handler: keep reading:[%zu]...\n",n);
          continue;
        } else {
          mem_deref(buffer);
          DEBUG_PRINTF("stdin_read_handle: returning...\n");
          return;
        }
      }
    }while (1);

    mem_deref(buffer);
    DEBUG_NOTICE("Exiting as EOF on stdin was reached\n");

    // Stop client & bye
    client_stop(client);
    before_exit();
    exit(0);
}

/*
 * Print the JSON encoded local parameters for the other peer.
 */
static void print_local_parameters(
        struct terminal_client* const client
) {
    struct odict* dict;

    // Encode parameters
    dict = client_encode_parameters(client);

    // Print as JSON
    DEBUG_INFO("Local Parameters:\n%H\n", json_encode_odict, dict);

    // Un-reference
    mem_deref(dict);
}

static void send_local_parameters(
		struct terminal_client* const client
){
	struct odict* dict;

	// Encode parameters
	dict = client_encode_parameters(client);

	// Send as JSON
	DEBUG_INFO("(%s) Sending local parameters\n", client->name);
	EOR(websock_send(client->ws_connection, WEBSOCK_TEXT, "%H", json_encode_odict, dict));


	// Un-reference
	mem_deref(dict);
}

/*
 * Print the local candidate. Open a connection to the WS server in
 * case all candidates have been gathered.
 */
static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct terminal_client* const client = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Print or send local parameters (if last candidate)
    if (!candidate) {
    	DEBUG_NOTICE("Last candidate received ...\n");
    	send_local_parameters(client);
    }
}

/*
 * Write the received data channel message's data to the PTY (or handle
 * a control message).
 */
void data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct terminal_client_channel* const client_channel = channel->arg;
    struct terminal_client* const client =
            (struct terminal_client* const) channel->client;
    size_t const length = mbuf_get_left(buffer);
    (void) flags;
    DEBUG_PRINTF("(%s.%s) Received %zu bytes\n",
                 client->name, channel->label, length);

    if (flags & RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_BINARY) {
        DEBUG_PRINTF("(%s.%s) binary datachannel message - ignoring\n",
                     client->name, channel->label);
    } else {
        // TODO: write to STDOUT

        DEBUG_PRINTF("(%s.%s) Ignoring %zu bytes received from data channel...\n",
                     client->name, channel->label, length);
        DEBUG_PRINTF("(%s.%s) ... completed!\n", client->name, channel->label);
    }
}

/*
 * Stop the PTY.
 */
static void stop_process(
        struct terminal_client_channel* const channel
) {
    DEBUG_INFO("Closing client channel\n");
}

/*
 * Stop the forked process on error event.
 */
static void data_channel_error_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct terminal_client_channel* const client_channel = channel->arg;

    DEBUG_INFO("(%s.%s) data_channel error", channel->client->name, channel->label);

    // Print error event
    default_data_channel_error_handler(arg);

    // Stop forked process
    if (client_channel->pid != -1) {
        DEBUG_INFO("(%s.%s) Stopping process\n", channel->client->name, channel->label);
    }
    stop_process(client_channel);
}

/*
 * Stop the forked process on close event.
 */
void data_channel_close_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct terminal_client_channel* const client_channel = channel->arg;

    DEBUG_INFO("(%s.%s) data_channel closed", channel->client->name, channel->label);

    // Print close event
    default_data_channel_close_handler(arg);

    // Stop forked process
    if (client_channel->pid != -1) {
        DEBUG_INFO("(%s.%s) Stopping process\n", channel->client->name, channel->label);
    }
    stop_process(client_channel);
}

/*
 * Send the PTY's data on the data channel.
 */
static void pty_read_handler(
        int flags,
        void* arg
) {
    struct data_channel_helper* const channel = arg;
    struct terminal_client_channel* const client_channel = channel->arg;
    struct terminal_client* const client =
            (struct terminal_client* const) channel->client;
    ssize_t length;
    (void) flags;

    // Create buffer
    struct mbuf* const buffer = mbuf_alloc(PIPE_READ_BUFFER);

    // Read from PTY into buffer
    // TODO: Handle EAGAIN?
    DEBUG_PRINTF("(%s.%s) Reading from process...\n", client->name, channel->label);
    length = read(client_channel->pty, mbuf_buf(buffer), mbuf_get_space(buffer));
    if (length == -1) {
        switch (errno) {
            case EIO:
                // This happens when invoking 'exit' or similar commands
                length = 0;
                break;
            default:
                EOR(errno);
                break;
        }
    }
    mbuf_set_end(buffer, (size_t) length);
    DEBUG_PRINTF("(%s.%s) ... read %zu bytes\n",
                 client->name, channel->label, mbuf_get_left(buffer));

    // Process terminated?
    if (length == 0) {
        // Stop listening
        if (client_channel->pid != -1) {
            DEBUG_INFO("(%s.%s) Stopping process\n", channel->client->name, channel->label);
        }
        stop_process(client_channel);

        // Close data channel
        EOE(rawrtc_data_channel_close(channel->channel));

        // Unreference helper
        mem_deref(channel);
    } else {
        // Send the buffer
        DEBUG_PRINTF("(%s.%s) Sending %zu bytes\n", client->name, channel->label, length);
        EOE(rawrtc_data_channel_send(channel->channel, buffer, false));
    }

    // Clean up
    mem_deref(buffer);
}

/*
 * Fork and start the process on open event.
 */
static void data_channel_open_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct terminal_client_channel* const client_channel = channel->arg;
    struct terminal_client* const client =
            (struct terminal_client* const) channel->client;
    int pty;
    struct data_channel_helper* removed;

    DEBUG_PRINTF("(%s.%s) DataChannel opened\n", client->name, channel->label);

    // Print open event
    default_data_channel_open_handler(arg);


    // Listen on PTY
    //EOR(fd_listen(client_channel->pty, FD_READ, pty_read_handler, channel));
}

static void terminal_client_channel_destroy(
        void* arg
) {
    struct terminal_client_channel* const client_channel = arg;

    // Stop process
    stop_process(client_channel);
}

/*
 * Handle the newly created data channel.
 */
static void data_channel_handler(
        struct rawrtc_data_channel* const channel, // read-only, MUST be referenced when used
        void* const arg // will be casted to `struct client*`
) {
    struct terminal_client* const client = arg;
    struct terminal_client_channel* client_channel;
    struct data_channel_helper* channel_helper;

    DEBUG_PRINTF("(%s) in data_channel_handler\n", client->name);

    // Print channel
    default_data_channel_handler(channel, arg);

    // Create terminal client channel instance
    client_channel = mem_zalloc(sizeof(*client_channel), terminal_client_channel_destroy);
    if (!client_channel) {
        EOE(RAWRTC_CODE_NO_MEMORY);
        return;
    }

    // Set fields
    client_channel->pid = -1;
    client_channel->pty = -1;

    // Create data channel helper instance
    // Note: In this case we need to reference the channel because we have not created it
    data_channel_helper_create_from_channel(&channel_helper, mem_ref(channel), arg, client_channel);
    mem_deref(client_channel);

    // Add to list
    list_append(&client->data_channels, &channel_helper->le, channel_helper);

    // Set handler argument & handlers
    EOE(rawrtc_data_channel_set_arg(channel, channel_helper));
    EOE(rawrtc_data_channel_set_open_handler(channel, data_channel_open_handler));
    EOE(rawrtc_data_channel_set_buffered_amount_low_handler(
            channel, default_data_channel_buffered_amount_low_handler));
    EOE(rawrtc_data_channel_set_error_handler(channel, data_channel_error_handler));
    EOE(rawrtc_data_channel_set_close_handler(channel, data_channel_close_handler));
    EOE(rawrtc_data_channel_set_message_handler(channel, data_channel_message_handler));
}

void client_create_data_channel(
		struct terminal_client* const client
) {
	struct rawrtc_data_channel_parameters* channel_parameters;

	// Create data channel helper
	data_channel_helper_create(
			&client->data_channel, (struct client *) client, "data-channel-pipe");

	// Create data channel parameters
	EOE(rawrtc_data_channel_parameters_create(
			&channel_parameters, client->data_channel->label,
			RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0));

	// Create data channel
	EOE(rawrtc_data_channel_create(
			&client->data_channel->channel, client->data_transport,
			channel_parameters, NULL,
			data_channel_open_handler,
			default_data_channel_buffered_amount_low_handler,
			data_channel_error_handler, data_channel_close_handler,
			data_channel_message_handler, client->data_channel));

	// Add to list
    list_append(&client->data_channels, &client->data_channel->le, client->data_channel);

	// Un-reference
	mem_deref(channel_parameters);
}

void some_sctp_transport_state_change_handler(
        enum rawrtc_sctp_transport_state const state,
        void* const arg // will be casted to `struct client*`
) {
    // struct client* const client = arg;
    struct terminal_client* const client = arg;

    char const * const state_name = rawrtc_sctp_transport_state_to_name(state);

    default_sctp_transport_state_change_handler(state, arg);

    if (RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED == state){
        // Close WS connection
        EOR(websock_close(client->ws_connection, WEBSOCK_NORMAL_CLOSURE, NULL));
        client->ws_connection = mem_deref(client->ws_connection);
        DEBUG_NOTICE("(%s) WebSocket closed after SCTP connected.\n", client->name);


    	DEBUG_INFO("SCTP connected - DTLS role:%d ... \n",client->dtls_transport->role);
    	if(client->dtls_transport->role == 1) {
        	DEBUG_INFO("creating the DataChannel ...\n");
        	client_create_data_channel(client);
    	}
    }
}


static void client_init(
        struct terminal_client* const client
) {
    struct rawrtc_certificate* certificates[1];

    if (client->ws_uri) {
        // Create DNS client
        EOR(dnsc_alloc(&client->dns_client, NULL, NULL, 0));

        // Create HTTP client
        EOR(http_client_alloc(&client->http_client, client->dns_client));

        // Create WS Socket
        EOR(websock_alloc(&client->ws_socket, NULL, client));
    }

    // Generate certificates
    EOE(rawrtc_certificate_generate(&client->certificate, NULL));
    certificates[0] = client->certificate;

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &client->gatherer, client->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, client));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &client->ice_transport, client->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, client));

    // Create DTLS transport
    EOE(rawrtc_dtls_transport_create(
            &client->dtls_transport, client->ice_transport, certificates, ARRAY_SIZE(certificates),
            default_dtls_transport_state_change_handler, default_dtls_transport_error_handler,
            client));

    // Create SCTP transport
    EOE(rawrtc_sctp_transport_create(
            &client->sctp_transport, client->dtls_transport,
            client->local_parameters.sctp_parameters.port,
            data_channel_handler, some_sctp_transport_state_change_handler, client));

    // Get data transport
    EOE(rawrtc_sctp_transport_get_data_transport(
            &client->data_transport, client->sctp_transport));

}

static void client_start_gathering(
        struct terminal_client* const client
) {
    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(client->gatherer, NULL));
}

static void client_start_transports(
        struct terminal_client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;
    DEBUG_INFO("(%s) Starting transports\n", client->name);

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            client->ice_transport, client->gatherer, remote_parameters->ice_parameters,
            client->role));

    // Start DTLS transport
    EOE(rawrtc_dtls_transport_start(
            client->dtls_transport, remote_parameters->dtls_parameters));

    // Start SCTP transport
    EOE(rawrtc_sctp_transport_start(
            client->sctp_transport, remote_parameters->sctp_parameters.capabilities,
            remote_parameters->sctp_parameters.port));
}

static void parameters_destroy(
        struct parameters* const parameters
) {
    // Un-reference
    parameters->ice_parameters = mem_deref(parameters->ice_parameters);
    parameters->ice_candidates = mem_deref(parameters->ice_candidates);
    parameters->dtls_parameters = mem_deref(parameters->dtls_parameters);
    if (parameters->sctp_parameters.capabilities) {
        parameters->sctp_parameters.capabilities =
                mem_deref(parameters->sctp_parameters.capabilities);
    }
}

static void client_stop(
        struct terminal_client* const client
) {
    DEBUG_INFO("(%s) Stopping transports\n", client->name);

    // Clear data channels
    list_flush(&client->data_channels);

    // Stop all transports & gatherer
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Close WS connection
    if (client->ws_connection) {
        EOR(websock_close(client->ws_connection, WEBSOCK_GOING_AWAY, NULL));
    }

    // Stop listening on STDIN
    fd_close(STDIN_FILENO);

    // Un-reference & close
    parameters_destroy(&client->remote_parameters);
    parameters_destroy(&client->local_parameters);
    client->ws_connection = mem_deref(client->ws_connection);
    client->data_transport = mem_deref(client->data_transport);
    client->sctp_transport = mem_deref(client->sctp_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
    client->ws_socket = mem_deref(client->ws_socket);
    client->http_client = mem_deref(client->http_client);
    client->dns_client = mem_deref(client->dns_client);
    client->gather_options = mem_deref(client->gather_options);
    client->ws_uri = mem_deref(client->ws_uri);
}

static void client_apply_parameters(
        struct terminal_client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;
    DEBUG_INFO("(%s) Applying remote parameters\n", client->name);

    // Set remote ICE candidates
    EOE(rawrtc_ice_transport_set_remote_candidates(
            client->ice_transport, remote_parameters->ice_candidates->candidates,
            remote_parameters->ice_candidates->n_candidates));
}

static enum rawrtc_code client_decode_parameters(
        struct parameters* const parametersp,
        struct odict* const dict,
        struct terminal_client* const client
) {
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct odict* node;
    struct parameters parameters = {0};

    // Decode nodes
    error |= dict_get_entry(&node, dict, "iceParameters", ODICT_OBJECT, true);
    error |= get_ice_parameters(&parameters.ice_parameters, node);
    error |= dict_get_entry(&node, dict, "iceCandidates", ODICT_ARRAY, true);
    error |= get_ice_candidates(&parameters.ice_candidates, node, (struct client* const) client);
    error |= dict_get_entry(&node, dict, "dtlsParameters", ODICT_OBJECT, true);
    error |= get_dtls_parameters(&parameters.dtls_parameters, node);
    error |= dict_get_entry(&node, dict, "sctpParameters", ODICT_OBJECT, true);
    error |= get_sctp_parameters(&parameters.sctp_parameters, node);

    // Ok?
    if (error) {
        DEBUG_WARNING("(%s) Invalid remote parameters\n", client->name);
        goto out;
    }

out:
    if (error) {
        // Un-reference
        mem_deref(parameters.sctp_parameters.capabilities);
        mem_deref(parameters.dtls_parameters);
        mem_deref(parameters.ice_candidates);
        mem_deref(parameters.ice_parameters);
    } else {
        // Copy parameters
        memcpy(parametersp, &parameters, sizeof(parameters));
    }

    return error;
}

static void client_get_parameters(
        struct terminal_client* const client
) {
    struct parameters* const local_parameters = &client->local_parameters;

    // Get local ICE parameters
    EOE(rawrtc_ice_gatherer_get_local_parameters(
            &local_parameters->ice_parameters, client->gatherer));

    // Get local ICE candidates
    EOE(rawrtc_ice_gatherer_get_local_candidates(
            &local_parameters->ice_candidates, client->gatherer));

    // Get local DTLS parameters
    EOE(rawrtc_dtls_transport_get_local_parameters(
            &local_parameters->dtls_parameters, client->dtls_transport));

    // Get local SCTP parameters
    EOE(rawrtc_sctp_transport_get_capabilities(
            &local_parameters->sctp_parameters.capabilities));
    EOE(rawrtc_sctp_transport_get_port(
            &local_parameters->sctp_parameters.port, client->sctp_transport));
}

static struct odict* client_encode_parameters(
        struct terminal_client* const client
) {
    struct odict* dict;
    struct odict* node;

    // Get local parameters
    client_get_parameters(client);

    // Create dict
    EOR(odict_alloc(&dict, 16));

    // Create nodes
    EOR(odict_alloc(&node, 16));
    set_ice_parameters(client->local_parameters.ice_parameters, node);
    EOR(odict_entry_add(dict, "iceParameters", ODICT_OBJECT, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_ice_candidates(client->local_parameters.ice_candidates, node);
    EOR(odict_entry_add(dict, "iceCandidates", ODICT_ARRAY, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_dtls_parameters(client->local_parameters.dtls_parameters, node);
    EOR(odict_entry_add(dict, "dtlsParameters", ODICT_OBJECT, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_sctp_parameters(client->sctp_transport, &client->local_parameters.sctp_parameters, node);
    EOR(odict_entry_add(dict, "sctpParameters", ODICT_OBJECT, node));
    mem_deref(node);

    // Done
    return dict;
}

static void exit_with_usage(char* program) {
    DEBUG_WARNING("Usage: %s <ws-uri> [<sctp-port>] "
                  "[<ice-candidate-type> ...]\n", program);
    exit(1);
}

int main(int argc, char* argv[argc + 1]) {
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};
    char* const turn_threema_ch_urls[] = {"turn:turn.threema.ch:443"};
    struct terminal_client client = {0};
    (void) client.ice_candidate_types; (void) client.n_ice_candidate_types;

    // Initialise
    EOE(rawrtc_init());

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Check arguments length
    if (argc < 2) {
        exit_with_usage(argv[0]);
    }

    // Get WS URI (optional)
    if (re_regex(argv[1], strlen(argv[1]), ws_uri_regex, NULL) == 0) {
        EOE(rawrtc_sdprintf(&client.ws_uri, argv[1]));
        DEBUG_PRINTF("Using signaling URI: %s\n", client.ws_uri);
    } else {
    	DEBUG_PRINTF("Illegal signaling URI: %s\n", argv[1]);
    	exit_with_usage(argv[0]);
    }

    // Get SCTP port (optional)
    if (argc >= 3) {
    	if(!str_to_uint16(&client.local_parameters.sctp_parameters.port, argv[2])) {
    		DEBUG_PRINTF("Illegal SCTP port: %s\n", argv[2]);
    		exit_with_usage(argv[0]);
    	} else {
    		DEBUG_PRINTF("Using SCTP port: %s\n", argv[2]);
    	}
    }

    // Get enabled ICE candidate types to be added (optional)
    if (argc >= 3) {
    	DEBUG_PRINTF("Using ICE types: %s\n", argv[3]);
        ice_candidate_types = &argv[3];
        n_ice_candidate_types = (size_t) argc - 3;
    }

    // Create ICE gather options
    EOE(rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_POLICY_ALL));

/**/
    // Add ICE servers to ICE gather options
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, stun_google_com_urls, ARRAY_SIZE(stun_google_com_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE));

    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_threema_ch_urls, ARRAY_SIZE(turn_threema_ch_urls),
            "threema-angular", "Uv0LcCq3kyx6EiRwQW5jVigkhzbp70CjN2CJqzmRxG3UGIdJHSJV6tpo7Gj7YnGB",
            RAWRTC_ICE_CREDENTIAL_TYPE_PASSWORD));
/**/

    // Set client fields
    client.name = "A";
    client.ice_candidate_types = ice_candidate_types;
    client.n_ice_candidate_types = n_ice_candidate_types;
    client.gather_options = gather_options;
    list_init(&client.data_channels);

    // Setup client
    client_init(&client);

	DEBUG_NOTICE("Connecting signaling WebSocket ...\n");
	EOR(websock_connect(
		&client.ws_connection, client.ws_socket, client.http_client,
		client.ws_uri, 30000,
		ws_established_handler, ws_receive_handler, ws_close_handler,
		&client, NULL));

    // Listen on stdin
    EOR(fd_listen(STDIN_FILENO, FD_READ, stdin_read_handler, &client));

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop client & bye
    client_stop(&client);
    before_exit();
    return 0;
}

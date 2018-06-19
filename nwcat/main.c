/*
See LICENSE folder for this sample’s licensing information.

Abstract:
nwcat is a basic version of the standard netcat/nc tool that uses Network.framework.
 It supports TCP and UDP connections and listeners, with TLS/DTLS support.
*/

#include <Network/Network.h>

#include <err.h>
#include <getopt.h>

// Global Options

char *g_local_port = NULL;	// Local port flag
char *g_local_addr = NULL;	// Source Address

bool g_detached = false;	// Ignore stdin

bool g_listener = false;	// Create a listener

bool g_verbose = false;		// Verbose
int g_family = AF_UNSPEC; 	// Required address family

nw_connection_t g_inbound_connection = NULL;

nw_listener_t create_and_start_listener(char *, char *);
nw_connection_t create_outbound_connection(const char *, const char *);
void start_connection(nw_connection_t connection);
void start_send_receive_loop(nw_connection_t connection);

void
print_usage(int ret)
{
	fprintf(stderr, "usage: nwcat [-46bdhltuv] [-k tls_psk] [-p source_port]\n");
	fprintf(stderr, "\t [-s source_ip_address] [hostname/service-name] [port]\n");
	if (ret != 0) {
		exit(ret);
	}
}


int
main(int argc, char *argv[])
{
	int ch = 0;
	char *hostname = NULL;
    char *port = NULL;
    
    // loop scan input args for -x, if no arg, return -1, while be breaked.
	while ((ch = getopt(argc, argv,
						"46bdhk:lp:s:tuv")) != -1) {
		switch (ch) {
			case 'l': {
				g_listener = true;
				break;
			}
			case 0: {
				break;
			}
			default: {
				print_usage(1);
				break;
			}
		}
	}
	argc -= optind;
	argv += optind;
    
    // got the host + port
	// Validate options
	if (argv[0] && !argv[1]) {
	// listener
        hostname = NULL;
        port = argv[0];
    }
    else if (argv[0] && argv[1])
    {
        // outbound
		hostname = argv[0];
		port = argv[1];
    }

    if (g_listener)
    {
        nw_listener_t listener = create_and_start_listener(hostname, port);
        printf("create and start listener gzw \n");
		if (listener == NULL) {
			err(1, NULL);
		}

		dispatch_main();
    }
    else
    {
        nw_connection_t connection = connection = create_outbound_connection(hostname, port);
        printf("outbound gzw \n");
		if (connection == NULL) {
			err(1, NULL);
		}

		start_connection(connection);
		start_send_receive_loop(connection);
		dispatch_main();
	}

	// Unreached
}

/*
 * create_outbound_connection()
 * Returns a retained connection to a remote hostname and port.
 * Sets up TLS and local address/port as necessary.
 */
nw_connection_t create_outbound_connection(const char *name, const char *port)
{
    printf("creating_outbound_c\n");
	// treat the name as a hostname
	nw_endpoint_t endpoint = nw_endpoint_create_host(name, port);

	nw_parameters_t parameters = NULL;
	nw_parameters_configure_protocol_block_t configure_tls = NW_PARAMETERS_DISABLE_PROTOCOL;

    // Create a TCP connection
    parameters = nw_parameters_create_secure_tcp(configure_tls,
													 NW_PARAMETERS_DEFAULT_CONFIGURATION);


	nw_connection_t connection = nw_connection_create(endpoint, parameters);
	nw_release(endpoint);
	nw_release(parameters);

	return connection;
}

/*
 * start_connection()
 * Schedule a connection on the main queue, process events, and
 * start the connection.
 */
void
start_connection(nw_connection_t connection)
{
	nw_connection_set_queue(connection, dispatch_get_main_queue());

	nw_retain(connection); // Hold a reference until cancelled
	nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
		nw_endpoint_t remote = nw_connection_copy_endpoint(connection);
		errno = error ? nw_error_get_error_code(error) : 0;
		if (state == nw_connection_state_waiting) {
			warn("connect to %s port %u tcp failed, is waiting",
				 nw_endpoint_get_hostname(remote),
				 nw_endpoint_get_port(remote));
		} else if (state == nw_connection_state_failed) {
			warn("connect to %s port %u (%s) failed",
				 nw_endpoint_get_hostname(remote),
				 nw_endpoint_get_port(remote),
				 "tcp");
        } else if (state == nw_connection_state_ready) {
            printf("Connection to %s port %u (%s) succeeded!\n",
                   nw_endpoint_get_hostname(remote),
                   nw_endpoint_get_port(remote),
                   "tcp");
		} else if (state == nw_connection_state_cancelled) {
			// Release the primary reference on the connection
			// that was taken at creation time
			nw_release(connection);
		}
		nw_release(remote);
	});

	nw_connection_start(connection);
}

/*
 * create_and_start_listener()
 * Returns a retained listener on a local port and optional address.
 * Sets up TLS as necessary.
 * Schedules listener on main queue and starts it.
 */
nw_listener_t
create_and_start_listener(char *name, char *port)
{
	nw_parameters_t parameters = NULL;
	nw_parameters_configure_protocol_block_t configure_tls = NW_PARAMETERS_DISABLE_PROTOCOL;

    // Create a TCP listener
    parameters = nw_parameters_create_secure_tcp(configure_tls,
													 NW_PARAMETERS_DEFAULT_CONFIGURATION);

	// Bind to local address and port
	const char *address = name; // Treat name as local address if not bonjour
	if (address || port) {
		nw_endpoint_t local_endpoint = nw_endpoint_create_host(address ? address : "::", port ? port : "0");
		nw_parameters_set_local_endpoint(parameters, local_endpoint);
		nw_release(local_endpoint);
	}

	nw_listener_t listener = nw_listener_create(parameters);
	nw_release(parameters);  // 用完即释放

	nw_listener_set_queue(listener, dispatch_get_main_queue());

	nw_retain(listener); // Hold a reference until cancelled  开始绑定handler之前先持有
	nw_listener_set_state_changed_handler(listener, ^(nw_listener_state_t state, nw_error_t error) {
		errno = error ? nw_error_get_error_code(error) : 0;
		if (state == nw_listener_state_waiting) {
			if (g_verbose) {
				fprintf(stderr, "Listener on port %u (%s) waiting\n",
						nw_listener_get_port(listener),
						"tcp");
			}
		} else if (state == nw_listener_state_failed) {
			warn("listener (%s) failed",
				 "tcp");
		} else if (state == nw_listener_state_ready) {
			if (g_verbose) {
				fprintf(stderr, "Listener on port %u (%s) ready!\n",
						nw_listener_get_port(listener),
						"tcp");
            }
            
            printf("Listener on port %u (%s) ready!\n",
                   nw_listener_get_port(listener),
                   "tcp");
		} else if (state == nw_listener_state_cancelled) {
			// Release the primary reference on the listener
			// that was taken at creation time
			nw_release(listener);
		}
	});

	nw_listener_set_new_connection_handler(listener, ^(nw_connection_t connection) {
		if (g_inbound_connection != NULL) {
			// We only support one connection at a time, so if we already
			// have one, reject the incoming connection.
			nw_connection_cancel(connection);
		} else {
			// Accept the incoming connection and start sending
			// and receiving on it.
			g_inbound_connection = connection;
			nw_retain(g_inbound_connection);

			start_connection(g_inbound_connection);
			start_send_receive_loop(g_inbound_connection);
		}
	});

	nw_listener_start(listener);

	return listener;
}

/*
 * receive_loop()
 * Perform a single read on the supplied connection, and write data to
 * stdout as it is received.
 * If no error is encountered, schedule another read on the same connection.
 */
void
receive_loop(nw_connection_t connection)
{
	nw_connection_receive(connection, 1, UINT32_MAX, ^(dispatch_data_t content, nw_content_context_t context, bool is_complete, nw_error_t receive_error) {

		dispatch_block_t schedule_next_receive = ^{
			// If the context is marked as complete, and is the final context,
			// we're read-closed.
			if (is_complete &&
				context != NULL && nw_content_context_get_is_final(context)) {
				exit(0);
			}

			// If there was no error in receiving, request more data
			if (receive_error == NULL) {
				receive_loop(connection);
			}
		};

		if (content != NULL) {
			// If there is content, write it to stdout asynchronously
			schedule_next_receive = Block_copy(schedule_next_receive);
			dispatch_write(STDOUT_FILENO, content, dispatch_get_main_queue(), ^(__unused dispatch_data_t _Nullable data, int stdout_error) {
				if (stdout_error != 0) {
					errno = stdout_error;
					warn("stdout write error");
				} else {
					schedule_next_receive();
				}
				Block_release(schedule_next_receive);
			});
        }
        else
        {
			// Content was NULL, so directly schedule the next receive
			schedule_next_receive();
		}
	});
}

/*
 * send_loop()
 * Start reading from stdin on a dispatch source, and send any bytes on the given connection.
 */
void
send_loop(nw_connection_t connection)
{
    dispatch_read(STDIN_FILENO, 8192, dispatch_get_main_queue(), ^(dispatch_data_t _Nonnull read_data, int stdin_error) {
        if (stdin_error != 0) {
            errno = stdin_error;
            warn("stdin read error");
        }
        else if (read_data == NULL)
        {
            // NULL data represents EOF
            // Send a "write close" on the connection, by sending NULL data with the final message context marked as complete.
            // Note that it is valid to send with NULL data but a non-NULL context.
            nw_connection_send(connection, NULL, NW_CONNECTION_FINAL_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error) {
                if (error != NULL) {
                    errno = nw_error_get_error_code(error);
                    warn("write close error");
                }
                // Stop reading from stdin, so don't schedule another send_loop
            });
        }
        else
        {
            // Every send is marked as complete. This has no effect with the default message context for TCP,
            // but is required for UDP to indicate the end of a packet.
            nw_connection_send(connection, read_data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error) {
                if (error != NULL) {
                    errno = nw_error_get_error_code(error);
                    warn("send error");
                } else {
                    // Continue reading from stdin
                    send_loop(connection);
                }
            });
        }
    });
    
}

/*
 * start_send_receive_loop()
 * Start reading from stdin (when not detached) and from the given connection.
 * Every read on stdin becomes a send on the connection, and every receive on the
 * connection becomes a write on stdout.
 */
void
start_send_receive_loop(nw_connection_t connection)
{
	// Start reading from stdin
	//gzw temp send_loop(connection);

	// Start reading from connection
    
    receive_loop(connection);
}

using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Text;

namespace PowerPorts {
    /// <summary>
    /// Implements a TCP service interrogator.
    /// </summary>
    public class TcpInterrogator : IDisposable {

        #region Fields
        private AsyncCallback _connectCallback;
        private bool _isProcessing = true;
        private Encoding _msgEncoding = Encoding.UTF8;
        private TcpClient _client;
        private int _readTimeout = 5000;
        #endregion

        /// <summary>
        /// Constructs a new interrogator.
        /// </summary>
        public TcpInterrogator() {
            _connectCallback += new AsyncCallback( ConnectCallback );
        }

        /// <summary>
        /// Closes all open resources.
        /// </summary>
        public void Dispose() {
            if( _client != null ) {
                _client.Dispose();
                _client = null;
            }
        }

        /// <summary>
        /// Indicates if any port scan connections are still processing. Poll this flag to determine
        /// when the batch of scans you request have all completed.
        /// </summary>
        public bool IsProcessing {
            get {
                return _isProcessing;
            }
            private set {
                _isProcessing = value;
            }
        }

        /// <summary>
        /// Gets or sets the message encoding for the greeting and response.
        /// </summary>
        public Encoding MessageEncoding {
            get {
                return _msgEncoding;
            }
            set {
                if( value == null ) throw new ArgumentNullException();
                _msgEncoding = value;
            }
        }

        /// <summary>
        /// Gets or sets the greeting sent to the target host after connection.
        /// </summary>
        public string Greeting {
            get;
            set;
        }

        /// <summary>
        /// Gets the response from the target host.
        /// </summary>
        public string Response {
            get;
            private set;
        }

        public int ReadTimeout {
            get {
                return _readTimeout;
            }
            set {
                if( value > 100 && value < 30000 ) {
                    _readTimeout = value;
                } else {
                    _readTimeout = 5000;
                }
            }
        }

        /// <summary>
        /// Starts a port scan of a server and port. This method does not block.
        /// </summary>
        /// <param name="server">The IPv4 address of the server.</param>
        /// <param name="port">The port number.</param>
        /// <exception cref="ArgumentNullException">The server argument is null or empty.</exception>
        /// <exception cref="ArgumentException">The port specified is out of range. Valid ports are between 1 and 65535.</exception>
        /// <exception cref="FormatException">The server specified is not a valid IPv4 address.</exception>
        public void Interrogate( string server, int port ) {
            // Set the processing flag
            IsProcessing = true;

            // Throw for illegal arguments
            if( string.IsNullOrEmpty( server ) ) throw new ArgumentNullException( "server" );
            if( port < 1 || port > 65535 ) throw new ArgumentException( "port" );

            // Parse the IP address
            var target = IPAddress.Parse( server );

            // Create a TCP connection
            _client = new TcpClient();

            // Initiate network-layer connection to the target host
            _client.BeginConnect( target, port, _connectCallback, _client );
        }

        /// <summary>
        /// Occurs when the connection completes a connection attempt.
        /// </summary>
        /// <remarks>This is the async callback for TcpClient.BeginConnect.</remarks>
        /// <param name="asr">The callback result.</param>
        private void ConnectCallback( IAsyncResult asr ) {
            try {
                // Call end connect and check the result
                var connected = false;
                try {
                    _client.EndConnect( asr );
                    connected = true;
                } catch {
                    connected = false;
                }
                // Check for connection and read response
                if( connected ) {
                    // Pull the stream
                    using( var stream = _client.GetStream() ) {
                        // Send a message to the host
                        if( !String.IsNullOrEmpty( Greeting ) ) {    
                            var hello = _msgEncoding.GetBytes( Greeting );
                            stream.Write( hello, 0, hello.Length );
                        }
                        // Read from the host
                        byte[] buffer = new byte[1024];
                        stream.ReadTimeout = _readTimeout;
                        var read = stream.Read( buffer, 0, buffer.Length );
                        if( read > 0 ) {
                            Response = _msgEncoding.GetString( buffer, 0, read );
                        }
                    }
                }
            } finally {
                // Notify waiting parties
                IsProcessing = false;
            }
        }
    }
}
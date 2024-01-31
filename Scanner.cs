using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace PowerPorts {

    /// <summary>
    /// Maps a TCP/IP service port to a service name.
    /// </summary>
    public enum TcpService {
        Echo = 7,
        FtpData = 20,
        Ftp = 21,
        Ssh = 22,
        Telnet = 23,
        Smtp = 25,
        Dns = 53,
        Http = 80,
        Kerberos = 88,
        Pop3 = 110,
        HttpTls = 443,
        Smb = 445,
        SqlServer = 1433,
        HttpInternal = 8080
    }

    /// <summary>
    /// Encapulates a port scan result to one server and one port.
    /// </summary>
    public struct TcpScannerResult {

        /// <summary>
        /// The IP address of the host.
        /// </summary>
        public string Server;

        /// <summary>
        /// The port number scanned.
        /// </summary>
        public int Port;

        /// <summary>
        /// The response code: 0 for open, 1 for closed.
        /// </summary>
        public int Code;

        /// <summary>
        /// The result string, open or closed.
        /// </summary>
        public string Result;

        /// <summary>
        /// The service name typically found on the port.
        /// </summary>
        public TcpService Service {
            get {
                return (TcpService)Port;
            }
        }

        /// <summary>
        /// Determines of two results are the same.
        /// </summary>
        /// <param name="other">A reference to the other result.</param>
        /// <returns>True of the results are identical, otherwise false.</returns>
        public override bool Equals( object other ) {
            if( other == null ) {
                return false;
            }
            if( other is TcpScannerResult ) {
                TcpScannerResult o = (TcpScannerResult)other;
                return
                    string.Equals( this.Server, o.Server, StringComparison.OrdinalIgnoreCase ) &&
                    this.Port == o.Port &&
                    this.Code == o.Code &&
                    string.Equals( this.Result, o.Result, StringComparison.OrdinalIgnoreCase );
            } else {
                return false;
            }
        }

        /// <summary>
        /// Formats this result as a string including the server and port which can be used to
        /// index these results in a dictionary.
        /// </summary>
        /// <returns>The server and port as a formatted string separated by a hyphen.</returns>
        /// <example>If the server and port are 127.0.0.1 and 80, this returns "127.0.0.1-00080".</example>
        public override string ToString() {
            return string.Format( "{0}-{1:00000}", Server, Port );
        }

        /// <summary>
        /// Converts the string value of this result to a hashcode.
        /// </summary>
        /// <returns>The hashcode of the string output.</returns>
        public override int GetHashCode() {
            return ToString().GetHashCode();
        }
    }

    /// <summary>
    /// Encapsulates a TcpClient port scan session with a client, result, and processing flag.
    /// </summary>
    public class TcpScannerSession {

        /// <summary>
        /// Gets or sets the client object for this session.
        /// </summary>
        public TcpClient Client {
            get; set;
        }

        /// <summary>
        /// Gets or sets a flag to determine if this scanner is still attempting the connection.
        /// </summary>
        public bool Processing {
            get; set;
        }

        /// <summary>
        /// Gets or sets the result for the session.
        /// </summary>
        public TcpScannerResult Result {
            get; set;
        }

        public static string GenerateKey( string server, int port ) {
            return string.Format( "{0}-{1:00000}", server, port );
        }
    }

    /// <summary>
    /// Implements an asynchronous, thread-safe TCP/IP port scanner. 
    /// </summary>
    public class TcpScanner {

        #region Fields
        /// <summary>
        /// The collection of scan results.
        /// </summary>
        private ConcurrentBag<TcpScannerResult> _results;

        /// <summary>
        /// The callback delegate for clients to invoke.
        /// </summary>
        private AsyncCallback _connectCallback;

        /// <summary>
        /// The collection of scan sessions.
        /// </summary>
        private ConcurrentDictionary<string,TcpScannerSession> _sessions;
        #endregion

        /// <summary>
        /// Constructs a new port scanner.
        /// </summary>
        public TcpScanner() {
            _results = new ConcurrentBag<TcpScannerResult>();
            _connectCallback += new AsyncCallback( ConnectCallback );
            _sessions = new ConcurrentDictionary<string,TcpScannerSession>();
        }

        /// <summary>
        /// Indicates if any port scan connections are still processing. Poll this flag to determine
        /// when the batch of scans you request have all completed.
        /// </summary>
        public bool IsProcessing {
            get {
                bool processing = false;
                foreach( TcpScannerSession s in _sessions.Values ) {
                    processing = processing || s.Processing;
                }
                return processing;
            }
        }

        /// <summary>
        /// Gets the collection of all the scanner results.
        /// </summary>
        public ConcurrentBag<TcpScannerResult> Results {
            get {
                return _results;
            }
        }

        /// <summary>
        /// Starts a port scan of a server and port. This method does not block.
        /// </summary>
        /// <param name="server">The IP address of the server.</param>
        /// <param name="port">The port number.</param>
        /// <exception cref="ArgumentNullException">The server argument is null or empty.</exception>
        /// <exception cref="ArgumentException">The port specified is out of range. Valid ports are between 1 and 65535.</exception>
        /// <exception cref="FormatException">The server specified is not a valid IPv4 address.</exception>
        public void StartScan( string server, int port ) {
            // Throw for illegal arguments
            if( string.IsNullOrEmpty( server ) ) throw new ArgumentNullException( "server" );
            if( port < 1 || port > 65535 ) throw new ArgumentException( "port" );

            // Generate a session key
            var key = TcpScannerSession.GenerateKey( server, port );

            // Check active scan sessions and skip if we have a duplicate
            if( _sessions.ContainsKey( key ) ) {
                return;
            }

            // Parse the IP address
            var target = IPAddress.Parse( server );

            // Create a TCP connection
            TcpClient client = new TcpClient();

            // Construct the session and assign parameters
            var session = new TcpScannerSession() {
                Client = client,
                Processing = true,
                Result = new TcpScannerResult() {
                    Server = server,
                    Port = port,
                    Code = 99,
                    Result = "connecting"
                }
            };

            // Register the session for watch
            _sessions.GetOrAdd( key, session );

            // Start the port scan
            client.BeginConnect( target, port, _connectCallback, session );
        }

        /// <summary>
        /// Occurs when the port scanner completes a connection attempt.
        /// </summary>
        /// <remarks>This is the async callback for TcpClient.BeginConnect.</remarks>
        /// <param name="asr">The callback result.</param>
        private void ConnectCallback( IAsyncResult asr ) {
            // Fetch the connection information
            var session = asr.AsyncState as TcpScannerSession;
            var result = session.Result;
            var key = TcpScannerSession.GenerateKey( result.Server, result.Port );

            // Call end connect and check the result
            try {
                session.Client.EndConnect( asr );
                result.Code = 0;
                result.Result = "open";
            } catch {
                result.Code = 1;
                result.Result = "closed";
            }

            // Add the port scan result to the collection
            _results.Add( result );

            // Kill the client
            session.Client.Dispose();
            session.Client = null;

            // Notify callers of completion
            _sessions.TryRemove( key, out session );
            session.Processing = false;
        }
    }
}
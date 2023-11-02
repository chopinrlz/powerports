using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace PowerPorts {
    public struct TcpScannerResult {
        public string Server;
        public int Port;
        public int Code;
        public string Result;

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

        public override string ToString() {
            return string.Format( "{0}-{1:00000}", Server, Port );
        }

        public override int GetHashCode() {
            return ToString().GetHashCode();
        }
    }

    public class TcpScannerSession {
        public TcpClient Client {
            get; set;
        }

        public bool Processing {
            get; set;
        }

        public TcpScannerResult Result {
            get; set;
        }
    }

    public class TcpScanner {
        private ConcurrentBag<TcpScannerResult> _results;
        private AsyncCallback _connectCallback;
        private ConcurrentDictionary<string,TcpScannerSession> _sessions;

        public TcpScanner() {
            _results = new ConcurrentBag<TcpScannerResult>();
            _connectCallback += new AsyncCallback( ConnectCallback );
            _sessions = new ConcurrentDictionary<string,TcpScannerSession>();
        }

        public bool IsProcessing {
            get {
                bool processing = false;
                foreach( TcpScannerSession s in _sessions.Values ) {
                    processing = processing || s.Processing;
                }
                return processing;
            }
        }

        public ConcurrentBag<TcpScannerResult> Results {
            get {
                return _results;
            }
        }

        public void Connect( string server, int port ) {
            var key = string.Format( "{0}-{1:00000}", server, port );
            if( _sessions.ContainsKey( key ) ) {
                return;
            }
            var target = IPAddress.Parse(server);
            TcpClient client = new TcpClient();
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
            _sessions.GetOrAdd( key, session );
            var result = client.BeginConnect( target, port, _connectCallback, session );
        }

        public void ConnectCallback( IAsyncResult asr ) {
            var session = asr.AsyncState as TcpScannerSession;
            session.Processing = false;
            var result = session.Result;
            result.Code = 0;
            result.Result = "complete";
            _results.Add( result );
        }
    }
}
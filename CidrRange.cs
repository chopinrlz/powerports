using System;
using System.Collections.Generic;
using System.Net;

namespace PowerPorts {

    /// <summary>
    /// Parses a CIDR notation network address and enumerates all IPv4 host addresses within the subnet.
    /// </summary>
    /// <example>
    /// var range = new CidrRange("192.168.0.0/24");
    /// foreach (var ip in range.Addresses) { ... }
    /// </example>
    public class CidrRange {

        #region Fields
        private readonly IPAddress _networkAddress;
        private readonly int _prefixLength;
        private readonly uint _networkBits;
        private readonly uint _subnetMask;
        #endregion

        /// <summary>
        /// Constructs a new CidrRange from a CIDR notation string.
        /// </summary>
        /// <param name="cidr">A CIDR notation string, e.g. "192.168.0.0/24".</param>
        /// <exception cref="ArgumentNullException">cidr is null or empty.</exception>
        /// <exception cref="FormatException">cidr is not a valid CIDR notation IPv4 address.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The prefix length is not between 0 and 32.</exception>
        public CidrRange( string cidr ) {
            if( string.IsNullOrEmpty( cidr ) ) throw new ArgumentNullException( "cidr" );

            var parts = cidr.Split( '/' );
            if( parts.Length != 2 ) {
                throw new FormatException( "CIDR notation must be in the form address/prefixLength, e.g. 192.168.0.0/24." );
            }

            if( !IPAddress.TryParse( parts[0], out _networkAddress ) || _networkAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ) {
                throw new FormatException( $"'{parts[0]}' is not a valid IPv4 address." );
            }

            if( !int.TryParse( parts[1], out _prefixLength ) || _prefixLength < 0 || _prefixLength > 32 ) {
                throw new ArgumentOutOfRangeException( "cidr", "Prefix length must be between 0 and 32." );
            }

            _subnetMask = _prefixLength == 0 ? 0u : ( 0xFFFFFFFF << ( 32 - _prefixLength ) );
            _networkBits = IpToUint( _networkAddress ) & _subnetMask;
        }

        /// <summary>
        /// Gets the network address parsed from the CIDR string.
        /// </summary>
        public IPAddress NetworkAddress {
            get {
                return UintToIp( _networkBits );
            }
        }

        /// <summary>
        /// Gets the subnet mask derived from the prefix length.
        /// </summary>
        public IPAddress SubnetMask {
            get {
                return UintToIp( _subnetMask );
            }
        }

        /// <summary>
        /// Gets the prefix length (e.g. 24 for a /24 network).
        /// </summary>
        public int PrefixLength {
            get {
                return _prefixLength;
            }
        }

        /// <summary>
        /// Gets the broadcast address for the subnet.
        /// </summary>
        public IPAddress BroadcastAddress {
            get {
                return UintToIp( _networkBits | ~_subnetMask );
            }
        }

        /// <summary>
        /// Gets the total number of addresses in the subnet, including network and broadcast addresses.
        /// </summary>
        public long TotalAddresses {
            get {
                return 1L << ( 32 - _prefixLength );
            }
        }

        /// <summary>
        /// Enumerates all IPv4 addresses in the subnet, including the network and broadcast addresses.
        /// </summary>
        public IEnumerable<IPAddress> Addresses {
            get {
                uint broadcast = _networkBits | ~_subnetMask;
                for( uint ip = _networkBits; ip <= broadcast; ip++ ) {
                    yield return UintToIp( ip );
                }
            }
        }

        /// <summary>
        /// Enumerates only the usable host addresses (excludes network and broadcast addresses).
        /// Returns all addresses for /31 and /32 per RFC 3021.
        /// </summary>
        public IEnumerable<IPAddress> HostAddresses {
            get {
                if( _prefixLength >= 31 ) {
                    foreach( var addr in Addresses ) {
                        yield return addr;
                    }
                    yield break;
                }
                uint broadcast = _networkBits | ~_subnetMask;
                for( uint ip = _networkBits + 1; ip < broadcast; ip++ ) {
                    yield return UintToIp( ip );
                }
            }
        }

        /// <summary>
        /// Determines whether the given IP address falls within this subnet.
        /// </summary>
        /// <param name="address">The IPv4 address to test.</param>
        /// <returns>True if the address is within the subnet, otherwise false.</returns>
        /// <exception cref="ArgumentNullException">address is null.</exception>
        /// <exception cref="ArgumentException">address is not an IPv4 address.</exception>
        public bool Contains( IPAddress address ) {
            if( address == null ) throw new ArgumentNullException( "address" );
            if( address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ) {
                throw new ArgumentException( "Only IPv4 addresses are supported.", "address" );
            }
            return ( IpToUint( address ) & _subnetMask ) == _networkBits;
        }

        /// <summary>
        /// Returns the CIDR notation string for this range.
        /// </summary>
        public override string ToString() {
            return string.Format( "{0}/{1}", NetworkAddress, _prefixLength );
        }

        private static uint IpToUint( IPAddress address ) {
            var bytes = address.GetAddressBytes();
            return (uint)( ( bytes[0] << 24 ) | ( bytes[1] << 16 ) | ( bytes[2] << 8 ) | bytes[3] );
        }

        private static IPAddress UintToIp( uint value ) {
            return new IPAddress( new byte[] {
                (byte)( value >> 24 ),
                (byte)( value >> 16 ),
                (byte)( value >> 8 ),
                (byte)( value )
            } );
        }
    }
}

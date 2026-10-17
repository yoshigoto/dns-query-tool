(function (root) {
    const options = {
        SUPPORTED_QUERY_TYPES: Object.freeze([
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'PTR-x', 'SRV', 'CAA', 'ANY',
            'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'CDS', 'CDNSKEY', 'TA',
            'TLSA', 'SSHFP', 'NAPTR', 'CERT', 'IPSECKEY', 'HIP', 'DHCID',
            'SVCB', 'HTTPS', 'DNAME', 'NULL', 'HINFO', 'RP', 'AFSDB', 'SIG', 'KEY', 'LOC', 'KX', 'APL', 'DLV', 'SPF',
            'IXFR', 'AXFR'
        ]),
        SUPPORTED_QUERY_CLASSES: Object.freeze(['IN', 'CS', 'CH', 'HS', 'ANY'])
    };
    if (typeof module === 'object' && module.exports) module.exports = options;
    else root.DnsQueryOptions = options;
})(globalThis);

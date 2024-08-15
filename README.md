# FF-CARL

A utility library for automating Firefox' mTLS host:certificate preference assignment file (`ClientAuthRememberList.bin`).

## Overview
This should be paired with `policies.json` certificate configuration management as per Firefox
[policy-templates](https://mozilla.github.io/policy-templates/), particularly a
[Certificates -> Install](https://mozilla.github.io/policy-templates/#certificates--install) stanza for *filesystem* resident
certs and/or a [SecurityDevices](https://mozilla.github.io/policy-templates/#securitydevices) stanza for *PKCS#11* resident
certs.

For its *configuration*, FF-CARL currently requires x509 client certificates to be in **DER** format.  The library will panic if the certificate bytes are not that of DER encoding, or if the DER certificate is otherwise unable to be parsed.  Please be aware that the DER certificate being used for configuration doesn't need to be the *very same* certificate known to Firefox, just a DER encoded version of it!

## Example
Pull in the lib using your Cargo.toml file:

```toml
[dependencies]
ff-carl = "0.1.1"
```
And run an example (being sure to appropriately substitute filesystem paths):

```rust,no_run
use ff_carl::write_entry;
use ff_carl::EntryArgs;
use std::path::PathBuf;

fn main() -> Result<(), std::io::Error> {
     let der_cert = std::fs::read("/path/to/cert.der").unwrap();
     let entry_args = EntryArgs::new(
         "https", // scheme
         "mtls.cert-demo.com", // ascii_host
         443, // port
         "cert-demo.com", // base_domain
         der_cert.as_ref(), // DER cert byte array
     );

     let backing_path = PathBuf::from("/path/to/firefox/profile/ClientAuthRememberList.bin");

     write_entry(entry_args, backing_path)
}
```

To write *multiple* host:certificate ClientAuthRememberList *Entry* values, use the `ff_carl::write_entries` function.

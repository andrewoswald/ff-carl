/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! A trivially simple library to automate creation of Firefox' mTLS host:certificate assignment
//! `ClientAuthRememberList.bin` file.
//!
//! For a properly seamless mTLS experience, Firefox obviously needs to be aware of (and have access to) the
//! configured client certificate(s).  This is *typically* achieved by way of a [policies.json][policy-templates]
//! file, and specifically through a [Certificates -> Install][certificates-install] stanza (for filesystem resident
//! certs) and/or a [SecurityDevices][security-devices] stanza (for PKCS#11 resident certs).
//!
//! FF-CARL currently requires client x509 certificate \[u8\] to be in **DER** format.  The library will panic if not DER,
//! if the certificate is corrupt, or due to other unanticipated i/o issues.
//!
//! [policy-templates]: https://mozilla.github.io/policy-templates/
//! [certificates-install]: https://mozilla.github.io/policy-templates/#policiesjson-15
//! [security-devices]: https://mozilla.github.io/policy-templates/#policiesjson-89
//!
//! #### Example
//!
//! This (fictitious file paths) example shows a single host:certificate configuration.
//! ```
//! use ff_carl::write_entry;
//! use ff_carl::EntryArgs;
//! use std::path::PathBuf;
//!
//! fn main() -> Result<(), std::io::Error> {
//!     let der_cert = std::fs::read("/path/to/cert.der").unwrap();
//!     let entry_args = EntryArgs::new(
//!         "https", // scheme
//!         "mtls.cert-demo.com", // ascii_host
//!         443, // port
//!         "cert-demo.com", // base_domain
//!         der_cert.as_ref(), // DER cert byte array
//!     );
//!
//!     let backing_path = PathBuf::from("/path/to/firefox/profile/ClientAuthRememberList.bin");
//!
//!     write_entry(entry_args, backing_path)
//! }
//! ```
//! To configure *multiple* host:certificate assignments, use the [`write_entries()`] function.
//!
//! Please refer to inlined source documentation for more details on *ClientAuthRememberList.bin*'s
//! internal format and contents.
//!

use base64::prelude::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::nom::AsBytes;
use x509_parser::prelude::*;

/// The unambiguous, requisite host and DER certificate details used for creating ClientAuthRememberList *Entry* values.
pub struct EntryArgs<'a> {
    /// Scheme; for example: "https".
    scheme: &'a [u8],
    /// ASCII host; for example: "my.example.com".
    ascii_host: &'a [u8],
    /// port; for example: Option(8443)
    port: Option<String>,
    /// Base domain; for example (assuming `ascii_host` is `my.example.com`): "example.com".
    base_domain: &'a [u8],
    /// X509 certificate to associate for mTLS with the above host.
    cert: X509Certificate<'a>,
}

impl<'a> EntryArgs<'a> {
    /// Construct a new EntryArgs.  This will panic if the `der_cert` is not of DER format
    /// or if there are any certificate parsing issues.
    /// #### Example
    /// ```
    /// let entry_args = ff_carl::EntryArgs::new(
    ///    "https",
    ///    "mtls.cert-demo.com",
    ///    443,
    ///    "cert-demo.com",
    ///    der_cert_bytes,
    /// );
    /// ```
    pub fn new(
        scheme: &'a str,
        ascii_host: &'a str,
        port: u32,
        base_domain: &'a str,
        der_cert: &'a [u8],
    ) -> Self {
        // DER is very simple to parse; we've got a composition of:
        // * tags that distinguish types
        // * data length
        // * data of that respective length

        // let's encrypt has a really nice summary:
        // https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

        // However, we can simply make use of the x509-parser crate:
        let res = X509Certificate::from_der(der_cert);

        match res {
            Ok((_rem, cert)) => EntryArgs {
                scheme: scheme.as_bytes(),
                ascii_host: ascii_host.as_bytes(),
                port: match port {
                    // Firefox will default to 443 for https and 80 for http
                    // (although I can't imagine mTLS over http??)
                    80 | 443 => None,
                    p => Some(p.to_string()),
                },
                base_domain: base_domain.as_bytes(),
                cert,
            },
            _ => panic!("x509 parsing failed: {:?}", res),
        }
    }
}

/// Write a single ClientAuthRememberList *Entry* value to the given PathBuf.
pub fn write_entry(entry_args: EntryArgs, backing_path: PathBuf) -> Result<(), std::io::Error> {
    write_entries(vec![entry_args], backing_path)
}

/// Write *multiple* ClientAuthRememberList *Entry* values to the given PathBuf.
pub fn write_entries(
    entry_inputs: Vec<EntryArgs>,
    backing_path: PathBuf,
) -> Result<(), std::io::Error> {
    // NB: majority of this code was copied from Gecko source security/manager/ssl/data_storage/src/lib.rs.

    const KEY_LENGTH: usize = 256;
    const SLOT_LENGTH: usize = 1286;

    let mut backing_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(backing_path)?;

    let necessary_len = (entry_inputs.len() * SLOT_LENGTH) as u64;
    if backing_file.metadata()?.len() < necessary_len {
        backing_file.set_len(necessary_len)?;
    }

    let mut buf = vec![0u8; SLOT_LENGTH];

    for (slot_index, entry_input) in entry_inputs.iter().enumerate() {
        let mut buf_writer = buf.as_mut_slice();
        buf_writer.write_u16::<BigEndian>(0)?; // set checksum to 0 for now
        let mut checksum: u16 = 1; // the "score" defaults to a value of 1
        buf_writer.write_u16::<BigEndian>(1)?; // actually write out the score
        let last_accessed = now_in_days();
        checksum ^= last_accessed;
        buf_writer.write_u16::<BigEndian>(last_accessed)?;

        // --------------------------------------------------------------------------
        // =========================== ENTRY KEY DETAILS ============================
        // --------------------------------------------------------------------------
        // Entry key c++ reference code is at nsClientAuthRemember::GetEntryKey;
        // its contents consist of:
        // * The ascii host.
        // * ",,".
        // * An `OriginAttributes` suffix (c++ reference code is at OriginAttributes::CreateSuffix).
        //   The OriginAttributes suffix is a set of key/value pairs with '^' character separator
        //   between pairs.  It seems we only use the "partitionKey" key and its encoded value:
        //   * "^partitionKey="
        //   * "(<scheme>,<baseDomain>,[port])" (NOTE: the '(', ',', ')' characters get "percent
        //      encoded" treatment; please refer to https://en.wikipedia.org/wiki/Percent-encoding).
        //      Please note that the port is optional for standardized ports such as 80 and 443.
        // * Any remaining bytes (of the 256) get 0 padded.
        // ==========================================================================
        let entry_key = get_entry_key(entry_input).unwrap();

        for mut chunk in entry_key.chunks(2) {
            if chunk.len() == 1 {
                checksum ^= (chunk[0] as u16) << 8;
            } else {
                checksum ^= chunk.read_u16::<BigEndian>()?;
            }
        }

        buf_writer.write_all(&entry_key)?;

        let (key_remainder, mut buf_writer) = buf_writer.split_at_mut(KEY_LENGTH - entry_key.len());
        key_remainder.fill(0);

        // --------------------------------------------------------------------------
        // ======================== ENTRY VALUE DETAILS =============================
        // --------------------------------------------------------------------------
        // The entry value is effectively a key used in an internal certificate database,
        // the "certdb" (c reference code is at certdb.[c|h]).  Entry value c++ reference
        // code is at nsNSSCertificate::GetDbKey.  The entry value consists of:
        // * base64 encoded "dbkey" consisting of:
        //   * empty 4 bytes (this was intended to be the module ID, but it was never implemented)
        //   * empty 4 bytes (this was intended to be the slot ID, but it was never implemented)
        //   * 4 bytes <serial number length in big-endian order>
        //   * 4 bytes <DER-encoded issuer distinguished name length in big-endian order>
        //   * n bytes <bytes of serial number>
        //   * m bytes <DER-encoded issuer distinguished name>
        // * Any remaining bytes (of the 1,024) get 0 padded.
        // ==========================================================================
        let db_key = get_dbkey(entry_input).unwrap();

        for mut chunk in db_key.chunks(2) {
            if chunk.len() == 1 {
                checksum ^= (chunk[0] as u16) << 8;
            } else {
                checksum ^= chunk.read_u16::<BigEndian>()?;
            }
        }
        buf_writer.write_all(&db_key)?;
        buf_writer.fill(0);

        backing_file.seek(SeekFrom::Start((slot_index * SLOT_LENGTH) as u64))?;
        backing_file.write_all(&buf)?;
        backing_file.flush()?;
        backing_file.seek(SeekFrom::Start((slot_index * SLOT_LENGTH) as u64))?;
        backing_file.write_u16::<BigEndian>(checksum)?;
    }

    Ok(())
}

/// Returns the current day in days since the unix epoch, to a maximum of
/// u16::MAX days.
fn now_in_days() -> u16 {
    // NB: copied from security/manager/ssl/data_storage/src/lib.rs
    const SECONDS_PER_DAY: u64 = 60 * 60 * 24;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    (now.as_secs() / SECONDS_PER_DAY)
        .try_into()
        .unwrap_or(u16::MAX)
}

// We are assuming the usecase here to be mTLS, thus the `partitionKey=` treatment.
fn get_entry_key(entry_input: &EntryArgs) -> Result<Vec<u8>, std::io::Error> {
    const COMMA_COMMA_CARET: &[u8] = b",,^";
    const PARTITION_KEY_EQUALS: &[u8] = b"partitionKey=";
    const PERCENT_ENCODED_LEFT_PAREN: &[u8] = b"%28";
    const PERCENT_ENCODED_COMMA: &[u8] = b"%2C";
    const PERCENT_ENCODED_RIGHT_PAREN: &[u8] = b"%29";

    let buf_length = entry_input.ascii_host.len()
        + COMMA_COMMA_CARET.len()
        + PARTITION_KEY_EQUALS.len()
        + PERCENT_ENCODED_LEFT_PAREN.len()
        + entry_input.scheme.len()
        + PERCENT_ENCODED_COMMA.len()
        + entry_input.base_domain.len()
        + match &entry_input.port {
            Some(p) => PERCENT_ENCODED_COMMA.len() + p.as_bytes().len(),
            None => 0,
        }
        + PERCENT_ENCODED_RIGHT_PAREN.len();

    let mut buf = vec![0u8; buf_length];
    let mut buf_writer = buf.as_mut_slice();
    buf_writer.write_all(entry_input.ascii_host.as_bytes())?;
    buf_writer.write_all(COMMA_COMMA_CARET)?;
    buf_writer.write_all(PARTITION_KEY_EQUALS)?;
    buf_writer.write_all(PERCENT_ENCODED_LEFT_PAREN)?;
    buf_writer.write_all(entry_input.scheme.as_bytes())?;
    buf_writer.write_all(PERCENT_ENCODED_COMMA)?;
    buf_writer.write_all(entry_input.base_domain.as_bytes())?;
    if entry_input.port.is_some() {
        buf_writer.write_all(PERCENT_ENCODED_COMMA)?;
        buf_writer.write_all(entry_input.port.as_ref().unwrap().as_bytes())?;
    }
    buf_writer.write_all(PERCENT_ENCODED_RIGHT_PAREN)?;

    Ok(buf)
}

// "dbkey" is the "entry value", which is effectively the meat of the slot's value.
fn get_dbkey(entry_input: &EntryArgs) -> Result<Vec<u8>, std::io::Error> {
    let serial_bytes = entry_input.cert.raw_serial();
    let serial_bytes_len = serial_bytes.len();

    let issuer_raw = entry_input.cert.issuer.as_raw();
    let issuer_raw_len = issuer_raw.len();

    let buf_length = 4 // empty module ID
        + 4 // empty slot ID
        + 4 // serial number length
        + 4 // DER-encoded issuer distinguished name length
        + serial_bytes_len // length of raw serial number bytes
        + issuer_raw_len; // DER-encoded issuer distinguished name bytes

    let mut buf = vec![0u8; buf_length];
    let mut buf_writer = buf.as_mut_slice();

    buf_writer.write_u32::<BigEndian>(0)?; // module ID
    buf_writer.write_u32::<BigEndian>(0)?; // slot ID
    buf_writer.write_u32::<BigEndian>(serial_bytes_len as u32)?; // serial number length
    buf_writer.write_u32::<BigEndian>(issuer_raw_len as u32)?; // DER-encoded issuer distinguished name length
    buf_writer.write_all(serial_bytes)?; // raw serial number bytes
    buf_writer.write_all(issuer_raw)?; // raw DER-encoded issuer distinguished name bytes

    Ok(BASE64_STANDARD.encode(buf).into_bytes())
}

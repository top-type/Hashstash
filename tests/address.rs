use bech32::{Bech32, Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use hashstash::{
    address, crypto, node,
    types::{Hash, PublicKey},
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    chain_id: String,
    public_key: String,
    address: String,
}
fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("data/addresses.json")).unwrap()
}

#[test]
fn independent_vectors_roundtrip_and_preserve_all_32_key_bytes() {
    for vector in vectors() {
        let chain = node::parse_hash(&vector.chain_id).unwrap();
        let public = node::parse_key(&vector.public_key).unwrap();
        assert_eq!(address::encode(&public, &chain).unwrap(), vector.address);
        assert_eq!(vector.address.len(), 78);
        assert_eq!(
            address::hrp(&chain),
            format!("hsh{}", &vector.chain_id[..16])
        );
        assert_eq!(address::decode(&vector.address, &chain).unwrap(), public);
        assert_eq!(
            address::decode(&vector.address.to_uppercase(), &chain).unwrap(),
            public
        );
        assert_eq!(
            address::decode_any(&vector.address).unwrap(),
            (address::hrp(&chain), public)
        );
        assert_eq!(
            node::parse_account(&vector.address, &chain).unwrap(),
            public
        );
        assert_eq!(
            node::parse_account(&vector.public_key, &chain).unwrap(),
            public
        );
        assert!(node::parse_key(&vector.address).is_err());
    }
}

#[test]
fn single_character_mutations_deletions_and_insertions_are_rejected() {
    let vector = vectors().remove(0);
    let chain = node::parse_hash(&vector.chain_id).unwrap();
    for index in 0..vector.address.len() {
        for replacement in b"0123456789abcdefghijklmnopqrstuvwxyz" {
            let mut bytes = vector.address.as_bytes().to_vec();
            if bytes[index] == *replacement {
                continue;
            }
            bytes[index] = *replacement;
            assert!(
                address::decode(std::str::from_utf8(&bytes).unwrap(), &chain).is_err(),
                "accepted mutation at {index}"
            );
        }
        let mut deleted = vector.address.clone();
        deleted.remove(index);
        assert!(address::decode(&deleted, &chain).is_err());
        let mut inserted = vector.address.clone();
        inserted.insert(index, 'q');
        assert!(address::decode(&inserted, &chain).is_err());
    }
    let mut mixed = vector.address.clone();
    mixed.replace_range(0..1, "H");
    assert!(address::decode(&mixed, &chain).is_err());
    assert!(address::decode(&format!(" {}", vector.address), &chain).is_err());
    assert!(address::decode(&format!("{}\n", vector.address), &chain).is_err());
}

// Independent checksum calculation from BIP350's reference algorithm. This
// lets the tests construct bad payloads with otherwise correct checksums.
const ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
fn words_address(prefix: &str, words: &[u8]) -> String {
    let expanded = prefix
        .bytes()
        .map(|c| c >> 5)
        .chain([0])
        .chain(prefix.bytes().map(|c| c & 31));
    let mut checksum = 1u32;
    for value in expanded.chain(words.iter().copied()).chain([0; 6]) {
        let high = checksum >> 25;
        checksum = ((checksum & 0x1ffffff) << 5) ^ u32::from(value);
        for (index, generator) in [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            .iter()
            .enumerate()
        {
            if (high >> index) & 1 != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum ^= 0x2bc830a3;
    let suffix = words
        .iter()
        .copied()
        .chain((0..6).map(|i| ((checksum >> (5 * (5 - i))) & 31) as u8))
        .map(|w| ALPHABET[w as usize] as char)
        .collect::<String>();
    format!("{prefix}1{suffix}")
}

#[test]
fn wrong_network_checksum_variant_prefix_key_length_and_padding_are_rejected() {
    let chain: Hash = [1; 32];
    let public: PublicKey = crypto::public_key(&[4; 32]).unwrap();
    let text = address::encode(&public, &chain).unwrap();
    let prefix = address::hrp(&chain);
    let mut other_chain = chain;
    other_chain[0] ^= 1;
    assert!(address::decode(&text, &other_chain).is_err());
    let legacy = bech32::encode::<Bech32>(Hrp::parse(&prefix).unwrap(), &public).unwrap();
    assert!(address::decode(&legacy, &chain).is_err());
    for bad_prefix in [
        "hsm0101010101010101",
        "hsh010101010101010g",
        "hsh01010101010101",
        "hsh010101010101010101",
    ] {
        let encoded = bech32::encode::<Bech32m>(Hrp::parse(bad_prefix).unwrap(), &public).unwrap();
        assert!(address::decode_any(&encoded).is_err());
    }
    for length in [0, 1, 31, 33, 40] {
        let encoded =
            bech32::encode::<Bech32m>(Hrp::parse(&prefix).unwrap(), &vec![1; length]).unwrap();
        assert!(address::decode_any(&encoded).is_err());
    }
    for bad_key in [[0; 32], [255; 32]] {
        assert!(address::encode(&bad_key, &chain).is_err());
        let encoded = bech32::encode::<Bech32m>(Hrp::parse(&prefix).unwrap(), &bad_key).unwrap();
        assert!(address::decode_any(&encoded).is_err());
    }
    let mut words = text[20..72]
        .bytes()
        .map(|c| ALPHABET.iter().position(|&b| b == c).unwrap() as u8)
        .collect::<Vec<_>>();
    let canonical_last = words[51];
    assert_eq!(canonical_last & 15, 0);
    for padding in 1..16 {
        words[51] = canonical_last | padding;
        let bad = words_address(&prefix, &words);
        assert!(
            CheckedHrpstring::new::<Bech32m>(&bad).is_ok(),
            "test checksum must be valid"
        );
        assert!(
            address::decode(&bad, &chain).is_err(),
            "accepted nonzero padding {padding}"
        );
    }
}

#[test]
fn official_bip350_checksum_vectors_use_bech32m_not_bech32() {
    // https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#test-vectors-for-bech32m
    let valid = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];
    for value in valid {
        assert!(CheckedHrpstring::new::<Bech32m>(value).is_ok());
        assert!(CheckedHrpstring::new::<Bech32>(value).is_err());
        assert!(
            address::decode_any(value).is_err(),
            "generic vectors are not Hashstash addresses"
        );
    }
    let invalid = [
        " 1xj0phk",
        "\u{7f}1g6xzxy",
        "\u{80}1vctc34",
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
        "qyrz8wqd2c9m",
        "1qyrz8wqd2c9m",
        "y1b0jsk6g",
        "lt1igcx5c0",
        "in1muywd",
        "mm1crxm3i",
        "au1s5cgom",
        "M1VUXWEZ",
        "16plkw9",
        "1p2gdwpf",
    ];
    for value in invalid {
        assert!(value.len() > 90 || CheckedHrpstring::new::<Bech32m>(value).is_err());
        assert!(address::decode_any(value).is_err());
    }
}

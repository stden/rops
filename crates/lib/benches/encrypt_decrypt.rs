use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rops::{
    cryptography::{cipher::AES256GCM, hasher::SHA512},
    file::{
        builder::RopsFileBuilder,
        format::YamlFileFormat,
        state::{DecryptedFile, EncryptedFile},
        RopsFile,
    },
    integration::{AgeIntegration, Integration},
};

const AGE_RECIPIENT: &str = "age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569";
const AGE_SECRET_KEY: &str = "AGE-SECRET-KEY-1EQUCGFZH8UZKSZ0Z5N5T234YRNDT4U9H7QNYXWRRNJYDDVXE6FWSCPGNJ7";
const SMALL_ENTRIES: usize = 8;
const LARGE_ENTRIES: usize = 256;

type EncryptedYaml = RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>;
type DecryptedYaml = RopsFile<DecryptedFile<SHA512>, YamlFileFormat>;

fn plaintext(entries: usize) -> String {
    let mut document = String::new();
    for index in 0..entries {
        document.push_str(&format!("key_{index}: value-{index}\n"));
    }
    document
}

fn recipient() -> <AgeIntegration as Integration>::KeyId {
    AGE_RECIPIENT.parse().expect("age recipient is valid")
}

fn encrypt(plaintext: &str, key_id: &<AgeIntegration as Integration>::KeyId) -> EncryptedYaml {
    RopsFileBuilder::<YamlFileFormat>::new(plaintext)
        .expect("plaintext is valid yaml")
        .add_integration_key::<AgeIntegration>(key_id.clone())
        .encrypt::<AES256GCM, SHA512>()
        .expect("encryption succeeds")
}

fn decrypt(document: &str) -> DecryptedYaml {
    document
        .parse::<EncryptedYaml>()
        .expect("document is encrypted yaml")
        .decrypt()
        .expect("decryption succeeds")
}

fn encrypt_decrypt(criterion: &mut Criterion) {
    std::env::set_var(AgeIntegration::private_key_env_var_name(), AGE_SECRET_KEY);

    let key_id = recipient();
    let cases: Vec<_> = [SMALL_ENTRIES, LARGE_ENTRIES]
        .into_iter()
        .map(|entries| {
            let plaintext = plaintext(entries);
            let encrypted = encrypt(&plaintext, &key_id).to_string();
            (format!("{entries}-entries"), plaintext, encrypted)
        })
        .collect();

    let mut encrypt_group = criterion.benchmark_group("encrypt");
    for (id, plaintext, _) in &cases {
        encrypt_group.throughput(Throughput::Bytes(plaintext.len() as u64));
        encrypt_group.bench_function(id, |bencher| {
            bencher.iter(|| black_box(encrypt(black_box(plaintext), black_box(&key_id))));
        });
    }
    encrypt_group.finish();

    let mut decrypt_group = criterion.benchmark_group("decrypt");
    for (id, _, encrypted) in &cases {
        decrypt_group.throughput(Throughput::Bytes(encrypted.len() as u64));
        decrypt_group.bench_function(id, |bencher| {
            bencher.iter(|| black_box(decrypt(black_box(encrypted))));
        });
    }
    decrypt_group.finish();
}

criterion_group!(benches, encrypt_decrypt);
criterion_main!(benches);

use beceeded::{parser::{Parser, ParserConfig}, mnemonic::Mnemonic};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parser(c: &Criterion) {
    // Initialize the parser
    let parser = Parser::default().expect("Failed to create parser");
    
    // Test phrase
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Benchmark parsing
    c.bench_function("parse_standard_mnemonic", |b| {
        b.iter(|| parser.parse(black_box(phrase)))
    });
    
    // Benchmark mnemonic creation
    c.bench_function("mnemonic_from_phrase", |b| {
        b.iter(|| Mnemonic::from_phrase(black_box(phrase), parser.clone()))
    });
    
    // Benchmark mnemonic generation
    c.bench_function("mnemonic_generation", |b| {
        b.iter(|| Mnemonic::generate(black_box(12), parser.clone()))
    });
}

criterion_group!(benches, bench_parser);
criterion_main!(benches); 
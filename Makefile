.PHONY: all rust cpp input clean test

BLOCK ?= 0
OUTPUT ?= build/block_input.bin

all: rust cpp

rust:
	cargo build --release --manifest-path rust-input-gen/Cargo.toml

test:
	cargo test --manifest-path rust-input-gen/Cargo.toml

input: rust
	cargo run --release --manifest-path rust-input-gen/Cargo.toml -- \
		--block $(BLOCK) --output $(OUTPUT)

cpp:
	cmake -S cpp-guest -B cpp-guest/build
	cmake --build cpp-guest/build

clean:
	cargo clean --manifest-path rust-input-gen/Cargo.toml
	rm -rf cpp-guest/build build

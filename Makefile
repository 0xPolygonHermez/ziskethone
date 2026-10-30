.PHONY: all rust cpp input clean test help bridge guest-test elf-test elf exex proof-engine \
        eest killer eest-fixtures killer-fixtures toolchain-check

BLOCK ?= 0
OUTPUT ?= build/block_input.bin

# EVM backend (evmone | zevm) and chain (mainnet | sepolia) of the guest builds.
EVM_BACKEND ?= evmone
CHAIN       ?= mainnet
JOBS        ?= $(shell nproc)

# Test fixtures, downloaded once from ethereum/execution-specs releases.
FIXTURES       ?= build/fixtures
EEST_RELEASE   ?= tests@v21.0.1
KILLER_RELEASE ?= tests-zkevm-benchmark@v21.0.5
KILLER_GAS     ?= 0200M
EEST_PATHS     ?= $(FIXTURES)/eest/fixtures/blockchain_tests
KILLER_PATHS   ?= $(FIXTURES)/killer-$(KILLER_GAS)/fixtures/blockchain_tests
KILLER_JOBS    ?= 4
ZISKEMU        ?= $(shell command -v ziskemu || echo $(HOME)/.zisk/bin/ziskemu)
RELEASES_URL   := https://github.com/ethereum/execution-specs/releases/download

# xpack riscv-none-elf-gcc 14 or 16 (see AGENTS.md). Set RISCV_GCC_BIN to its
# bin/ when it isn't on PATH.
RISCV_GCC_BIN ?=
ifneq ($(RISCV_GCC_BIN),)
export PATH := $(RISCV_GCC_BIN):$(PATH)
endif

ROOT       := $(CURDIR)
TOOLCHAIN  := $(ROOT)/cpp-guest/zisk/toolchain.cmake
# Test builds take the fork from the input (EEST replays every fork at
# synthetic times); deployed builds use the compile-time fork schedule.
TEST_HOST  := cpp-guest/build-test-$(EVM_BACKEND)
TEST_ELF   := cpp-guest/zisk/build-test-$(EVM_BACKEND)
DEPLOY_HOST:= cpp-guest/build-$(CHAIN)
DEPLOY_ELF := cpp-guest/zisk/build-$(CHAIN)-$(EVM_BACKEND)

all: rust cpp

help:
	@echo "build:   rust cpp elf exex proof-engine bridge guest-test elf-test"
	@echo "tests:   test  eest  killer"
	@echo "vars:    EVM_BACKEND=$(EVM_BACKEND) CHAIN=$(CHAIN) JOBS=$(JOBS) KILLER_JOBS=$(KILLER_JOBS)"
	@echo "         KILLER_GAS=$(KILLER_GAS) FIXTURES=$(FIXTURES) ZISKEMU=$(ZISKEMU)"
	@echo "         EEST_PATHS=... KILLER_PATHS=... (subsets) RISCV_GCC_BIN=..."

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

# ----- deployment builds -----------------------------------------------------

# The ZisK ELF the prover runs: ZEG_CHAIN=$(CHAIN), fork from the schedule,
# EIP-8025 public output. The host configure provides evmone's patched source.
# Every option that changes what the ELF proves is passed explicitly and the
# ELF dir is configured --fresh, so nothing leaks in from an old CMakeCache
# (audit H8). The ELF records them: strings <elf> | grep ZEG_BUILD_FLAGS.
DEPLOY_FLAGS := -DEVM_BACKEND=$(EVM_BACKEND) -DZEG_CHAIN=$(CHAIN) \
	-DZEG_FORK_FROM_INPUT=OFF -DZEG_PUBLIC_OUTPUT=npr
DEPLOY_ELF_FLAGS := -DCMAKE_BUILD_TYPE=Release -DZEG_HEAP_STATS=OFF \
	-DZEG_JUMPDEST_SW=OFF -DZEG_BSWAP_BUILTIN=ON -DZEG_ZISK_DMA=OFF \
	-DZEG_ANALYSIS_CACHE_SLOTS=1152

elf: toolchain-check
	cmake -S cpp-guest -B $(DEPLOY_HOST) $(DEPLOY_FLAGS)
	cmake --fresh -S cpp-guest/zisk -B $(DEPLOY_ELF) -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		$(DEPLOY_FLAGS) $(DEPLOY_ELF_FLAGS) \
		-DEVMONE_SRC=$(ROOT)/$(DEPLOY_HOST)/_deps/evmone-src
	cmake --build $(DEPLOY_ELF) --target zisk_eth_guest.elf -j $(JOBS)
	@echo "ELF: $(DEPLOY_ELF)/zisk_eth_guest.elf"

exex:
	cd reth-zisk-exex && cargo build --release

proof-engine:
	cd proof-engine && cargo build --release

toolchain-check:
	@command -v riscv-none-elf-g++ >/dev/null || { \
		echo "riscv-none-elf-g++ not found: put xpack riscv-none-elf-gcc 14 or 16 bin/ on PATH" \
		     "or pass RISCV_GCC_BIN=<dir>"; exit 1; }

# ----- test builds -----------------------------------------------------------

bridge:
	cargo build --release --manifest-path eest-witness-gen/Cargo.toml

guest-test:
	cmake -S cpp-guest -B $(TEST_HOST) -DEVM_BACKEND=$(EVM_BACKEND) -DZEG_FORK_FROM_INPUT=ON
	cmake --build $(TEST_HOST) -j $(JOBS)

elf-test: guest-test toolchain-check
	cmake -S cpp-guest/zisk -B $(TEST_ELF) -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DCMAKE_BUILD_TYPE=Release -DEVM_BACKEND=$(EVM_BACKEND) -DZEG_FORK_FROM_INPUT=ON \
		-DEVMONE_SRC=$(ROOT)/$(TEST_HOST)/_deps/evmone-src
	cmake --build $(TEST_ELF) --target zisk_eth_guest.elf -j $(JOBS)

# ----- fixtures (downloaded once; delete the .done stamp to refetch) ---------

$(FIXTURES)/eest/.done:
	mkdir -p $(@D)
	curl -fL --retry 3 -o $(@D)/fixtures.tar.gz \
		$(RELEASES_URL)/$(subst @,%40,$(EEST_RELEASE))/fixtures.tar.gz
	tar xzf $(@D)/fixtures.tar.gz -C $(@D) && rm $(@D)/fixtures.tar.gz
	touch $@

$(FIXTURES)/killer-$(KILLER_GAS)/.done:
	mkdir -p $(@D)
	curl -fL --retry 3 -o $(@D)/fixtures.tar.gz \
		$(RELEASES_URL)/$(subst @,%40,$(KILLER_RELEASE))/fixtures_zkevm-benchmark_$(KILLER_GAS).tar.gz
	tar xzf $(@D)/fixtures.tar.gz -C $(@D) && rm $(@D)/fixtures.tar.gz
	touch $@

eest-fixtures: $(FIXTURES)/eest/.done
killer-fixtures: $(FIXTURES)/killer-$(KILLER_GAS)/.done

# ----- test suites -----------------------------------------------------------

# Every EEST blockchain test through bridge → input → host guest.
eest: rust bridge guest-test eest-fixtures
	scripts/eest_sweep.sh -g $(TEST_HOST)/zisk_eth_guest -o build/eest-$(EVM_BACKEND) \
		-j $(JOBS) $(EEST_PATHS)

# The zkevm-benchmark worst-case blocks ($(KILLER_GAS) gas) on the ZisK ELF in ziskemu.
killer: rust bridge elf-test killer-fixtures
	scripts/killer_sweep.sh -g $(TEST_HOST)/zisk_eth_guest -e $(TEST_ELF)/zisk_eth_guest.elf \
		-z $(ZISKEMU) -o build/killer-$(KILLER_GAS)-$(EVM_BACKEND) -j $(KILLER_JOBS) $(KILLER_PATHS)

clean:
	cargo clean --manifest-path rust-input-gen/Cargo.toml
	rm -rf cpp-guest/build
	find build -mindepth 1 -maxdepth 1 ! -name fixtures -exec rm -rf {} + 2>/dev/null || true

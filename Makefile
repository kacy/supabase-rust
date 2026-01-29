.PHONY: build test lint clean check doc publish release-patch release-minor release-major help

# Default target
help:
	@echo "Available targets:"
	@echo "  build         - Build the library"
	@echo "  test          - Run all tests"
	@echo "  lint          - Run clippy and check formatting"
	@echo "  check         - Run all checks (build, test, lint)"
	@echo "  clean         - Clean build artifacts"
	@echo "  doc           - Generate documentation"
	@echo "  doc-open      - Generate and open documentation"
	@echo ""
	@echo "Release targets:"
	@echo "  release-patch - Bump patch version (0.1.2 -> 0.1.3)"
	@echo "  release-minor - Bump minor version (0.1.2 -> 0.2.0)"
	@echo "  release-major - Bump major version (0.1.2 -> 1.0.0)"
	@echo "  publish       - Publish to crates.io (run release-* first)"
	@echo ""
	@echo "Current version: $$(grep '^version' Cargo.toml | head -1 | cut -d'\"' -f2)"

# Build the library
build:
	cargo build --lib

# Run all tests
test:
	cargo test

# Run clippy and check formatting
lint:
	cargo clippy -- -D warnings
	cargo fmt -- --check

# Format code
fmt:
	cargo fmt

# Run all checks
check: lint build test
	@echo "All checks passed!"

# Clean build artifacts
clean:
	cargo clean

# Generate documentation
doc:
	cargo doc --no-deps

# Generate and open documentation
doc-open:
	cargo doc --no-deps --open

# Get current version
version:
	@grep '^version' Cargo.toml | head -1 | cut -d'"' -f2

# Bump patch version (0.1.2 -> 0.1.3)
release-patch:
	@CURRENT=$$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT | cut -d. -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	sed -i '' "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" Cargo.toml; \
	echo "Bumped version: $$CURRENT -> $$NEW_VERSION"

# Bump minor version (0.1.2 -> 0.2.0)
release-minor:
	@CURRENT=$$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	NEW_MINOR=$$((MINOR + 1)); \
	NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	sed -i '' "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" Cargo.toml; \
	echo "Bumped version: $$CURRENT -> $$NEW_VERSION"

# Bump major version (0.1.2 -> 1.0.0)
release-major:
	@CURRENT=$$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	NEW_MAJOR=$$((MAJOR + 1)); \
	NEW_VERSION="$$NEW_MAJOR.0.0"; \
	sed -i '' "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" Cargo.toml; \
	echo "Bumped version: $$CURRENT -> $$NEW_VERSION"

# Publish to crates.io
publish: check
	@echo "Publishing to crates.io..."
	@echo "Make sure you have run 'cargo login' first!"
	cargo publish

# Dry run publish (check if package is ready)
publish-dry:
	cargo publish --dry-run

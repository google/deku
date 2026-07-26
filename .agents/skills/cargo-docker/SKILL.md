---
name: cargo-docker
description: Instrukcje i zasady dotyczące uruchamiania kompilatora cargo w celu zbudowania test/tags/src/main.rs oraz projektów Rust (cargo) w tym repozytorium przy użyciu kontenera Docker deku_test:latest. Użyj tego skilla, gdy musisz zbudować, skompilować lub uruchomić test/tags/src/main.rs lub komendy cargo w katalogu test/tags.
---

# Kompilacja projektów Cargo / Rust (`test/tags/src/main.rs`) w Dockerze

Aby skompilować lub zbudować plik "test/tags/src/main.rs" (oraz ogólnie projekt Rust w katalogu `test/tags/`), **nie należy uruchamiać komendy `cargo` bezpośrednio na hoście**.

Zamiast tego, kompilator `cargo` musi być uruchamiany wewnątrz kontenera Docker **`deku_test:latest`**.

## Rekomendowane polecenie kompilacji

Z głównego katalogu repozytorium:

```bash
# Uruchomienie kompilacji przez Docker (w trybie nieinteraktywnym dla agenta/skryptów):
docker run --rm --network="host" -v ~/linux-trees:/kernel -v $(pwd):/deku -v /tmp:/tmp --workdir /deku/test/tags deku_test:latest cargo build
```

Jeśli potrzebne jest uruchomienie interaktywne lub z parametrami `-it` / `-t` (zgodnie z konwencją w `test/README` i `test/common.sh`):

```bash
docker run -it --network="host" -v ~/linux-trees:/kernel -v $(pwd):/deku -v /tmp:/tmp --workdir /deku/test/tags deku_test:latest cargo build
```

## Przykłady innych operacji Cargo w kontenerze `deku_test:latest`

- **Sprawdzenie poprawności kodu (`cargo check`):**
  ```bash
  docker run --rm --network="host" -v ~/linux-trees:/kernel -v $(pwd):/deku -v /tmp:/tmp --workdir /deku/test/tags deku_test:latest cargo check
  ```

- **Uruchomienie testów (`cargo test`):**
  ```bash
  docker run --rm --network="host" -v ~/linux-trees:/kernel -v $(pwd):/deku -v /tmp:/tmp --workdir /deku/test/tags deku_test:latest cargo test
  ```

- **Uruchomienie programu (`cargo run`):**
  ```bash
  docker run --rm --network="host" -v ~/linux-trees:/kernel -v $(pwd):/deku -v /tmp:/tmp --workdir /deku/test/tags deku_test:latest cargo run
  ```

> [!IMPORTANT]
> Zawsze upewnij się, że montujesz odpowiednie wolumeny (`-v $(pwd):/deku`, `-v ~/linux-trees:/kernel`, `-v /tmp:/tmp`) i ustawiasz katalog roboczy `--workdir /deku/test/tags` przed wywołaniem narzędzi Rust/Cargo w kontenerze `deku_test:latest`.

# morse-seal

`morse-seal` is a local sidecar for the [Morse](https://trymorse.ai) API. It runs on your machine, speaks the OpenAI API on `http://127.0.0.1:4141/v1`, and seals every content request to an AWS Nitro enclave before the request leaves your machine. Morse's relay, its load balancer, and its hosts see only ciphertext.

Before it seals anything, `morse-seal` checks the enclave's attestation document against the AWS Nitro root and against the image measurements that [morse-pins](https://github.com/trymorse/morse-pins) publishes, and it confirms that [morse-enclave](https://github.com/trymorse/morse-enclave) publishes the source of that image. If no enclave passes the check, the request fails. `morse-seal` never sends a content request unsealed.

You keep your OpenAI SDK and your code. You change the base URL.

## Install

Install with Go 1.27.4 or later:

```sh
go install github.com/trymorse/morse-seal/cmd/morse-seal@latest
```

Or download a binary for Linux, macOS, or Windows, on amd64 or arm64, from the [releases](https://github.com/trymorse/morse-seal/releases) page. `checksums.txt` in each release lists the SHA-256 of every archive. Each archive and the Docker image carry a GitHub build provenance attestation, which shows the workflow run and commit that built them:

```sh
gh attestation verify morse-seal_<version>_linux_amd64.tar.gz --repo trymorse/morse-seal
gh attestation verify oci://ghcr.io/trymorse/morse-seal:<version> --repo trymorse/morse-seal
```

Or run the container image:

```sh
docker run --rm -p 127.0.0.1:4141:4141 -e MORSE_API_KEY ghcr.io/trymorse/morse-seal --floor tee
```

The image listens on `0.0.0.0:4141` inside the container. Publish the port on `127.0.0.1` only, as above. Anyone who can reach the port can spend your key.

## Run it

1. Get an API key that starts with `sk_` from your Morse account.
2. Start the sidecar:

   ```sh
   MORSE_API_KEY=sk_... morse-seal --floor tee
   ```

   It prints the environment it seals to, the number of pinned images and the `morse-pins` commit they come from, and the address it listens on. Each time it first trusts an image, it prints the image's tag, the start of its PCR0, and that commit:

   ```
   morse-seal: trusting image v2026.11.0 pcr0 4a5a573c7089812e… pinned by trymorse/morse-pins@45267a5a174f4e6ccd45c3ec40cfc2a1eddac310, source commit 9d57164c241b540a6eb9a909c143817374bf96c2
   ```

3. Point your SDK at `http://127.0.0.1:4141/v1`. The SDK's own API key can be any value. The sidecar adds your `sk_` key to the outer request.

Python:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:4141/v1", api_key="morse-seal")
stream = client.chat.completions.create(
    model="glm-5.3-tee",
    stream=True,
    messages=[{"role": "user", "content": "hi"}],
)
for chunk in stream:
    print(chunk.choices[0].delta.content or "", end="")
```

TypeScript:

```ts
import OpenAI from "openai";

const client = new OpenAI({ baseURL: "http://127.0.0.1:4141/v1", apiKey: "morse-seal" });
const stream = await client.chat.completions.create({
  model: "glm-5.3-tee",
  stream: true,
  messages: [{ role: "user", content: "hi" }],
});
for await (const chunk of stream) {
  process.stdout.write(chunk.choices[0]?.delta?.content ?? "");
}
```

You can also set `OPENAI_BASE_URL=http://127.0.0.1:4141/v1` instead of passing `base_url` or `baseURL`.

## Flags

| Flag | Default | What it does |
| --- | --- | --- |
| `--key` | `$MORSE_API_KEY` | Your `sk_` key. It goes on the outer request only. |
| `--floor` | none | The lowest privacy tier a chat may use: `anon`, `private`, or `tee`. The sidecar sets `provider.min_privacy` inside the seal on every chat request that names none or a lower tier, so a request can raise the floor and cannot lower it. A model below the floor gets `400 privacy_floor_unmet`. The floor applies only to `POST /v1/chat/completions` and `POST /v1/chat/compact`, so with `--floor` set the sidecar answers every other content route, such as `/v1/messages`, `/v1/responses`, images, and search, with `400 floor_unsupported_route` rather than send it without the floor. Run a sidecar without `--floor` for those routes. |
| `--privacy-veil` | off | Ask for the Privacy Veil inside the seal on every chat request, so the enclave replaces the personal details in your messages with placeholders before the model's vendor reads them, and puts them back in the reply. A chat that sets `privacy_veil: false` gets `400 privacy_veil_required`, and other content routes and E2EE chats get `400 privacy_veil_not_applicable`. A reply the enclave did not mark `X-Privacy-Veil: applied` is withheld as `502 privacy_veil_missing`. Without the flag, a chat body's own `privacy_veil` still goes inside the seal. |
| `--listen` | `127.0.0.1:4141` | The address to serve the OpenAI API on. |
| `--pins-commit` | `main` of `morse-pins` | The `morse-pins` commit whose `enclave_pins.json` to trust, as a 40-character SHA. The commit must be in the history of `main`, or the sidecar does not start. The list stays at that commit until you change the flag. |
| `--pins` | none | A local `enclave_pins.json` to trust in place of `morse-pins`. You cannot pass it with `--pins-commit`. |
| `--source` | `https://github.com/trymorse/morse-enclave` | The repository whose tags publish the source of each pinned image. |
| `--upstream` | `https://inference.trymorse.ai` | The Morse API. `--upstream https://api.morseinference.com` reaches the same door under its second name, which serves only the text models marked uncensored. `https://api.trymorse.ai` refuses every `sk_` key with `403 use_inference_door`, so do not point the sidecar there. |
| `--env` | `prod` | The environment that the attestation documents and the pins must name: `prod` or `dev`. |
| `--dev` | off | Accept a Morse server that runs outside an enclave. Use it only for local development against a dev server. |

## What it proves

For each request, `morse-seal` seals the body to the keys of enclaves whose attestation documents pass every check below. If none pass, the request gets `502 attestation_failed`, which names each failed check.

- The document is a COSE_Sign1 signed with ES384.
- Its certificate chain runs from the AWS Nitro root to the signing certificate. The root is embedded in the binary and pinned by its SHA-256 fingerprint, `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`, which AWS publishes.
- Every certificate was valid when the document was issued.
- The document is at most 30 minutes old and at most 5 minutes ahead of the Morse server's clock.
- Its PCR0, PCR1, and PCR2 match an image that `enclave_pins.json` lists for the environment and does not mark revoked.
- The image's source is public. [morse-enclave](https://github.com/trymorse/morse-enclave) has a tag with the pin's `tag` name, and the commit message of that tag lists the same PCR0, PCR1, and PCR2. You can check out the tag, rebuild the image, and compare PCR0. A pin without a tag is refused. A confirmed image is remembered until the sidecar stops. A refused one is checked again after a minute, so a client that retries does not ask GitHub on every request.
- Its `user_data` names the enclave's 32-byte HPKE key for that environment.

The source check reads the tag list and that one commit over git's smart HTTP protocol, the protocol `git fetch` uses. It does not call the GitHub REST API, so the API's limit of 60 unauthenticated calls an hour does not apply, and the sidecar needs no GitHub token. It checks each image once and keeps the result while it runs. If GitHub cannot be reached, the image is not trusted, and the next request tries again.

The sidecar reads `enclave_pins.json` at a fixed commit of `morse-pins`. By default it resolves `main` to a commit at startup. When no enclave passes and one reports an image that no pin names, it resolves `main` again and checks once more, so a new release does not need a restart. With `--pins-commit`, the list stays at the commit you gave.

At startup, the sidecar checks that the `--pins-commit` commit is in the history of `main`. GitHub serves a commit from a fork of `morse-pins` under the name `morse-pins`, so without this check a commit that someone gives you could be a fork commit with a list that trusts a revoked image again. The sidecar makes one call to the GitHub REST API, `GET /repos/trymorse/morse-pins/compare/<commit>...main`, and the answer must be `ahead` or `identical`. If the commit is not in the history of `main`, or GitHub does not answer, the sidecar exits with status 2. This is the only REST API call the sidecar makes, so the limit of 60 unauthenticated calls an hour applies only to starts with `--pins-commit`.

These requests go to Morse without a seal, because Morse answers them without model content: `GET /v1/models`, `GET /v1/attestation`, `GET /v1/receipts/{id}`, and `GET /v1/videos/{id}`.

## What it does not prove

- **It does not hide usage.** Morse still sees who calls and when, the model, the token counts, the approximate request and reply sizes, and the timing of a streamed reply.
- **It protects content up to the `tee` tier.** The enclave opens the request. On an `anon` or `private` model the enclave forwards the prompt to the model vendor under Morse's account, and the vendor can read it. On a `tee` model the enclave sends the prompt only to a vendor enclave whose attestation it has checked. An `e2ee` model needs each request sealed to the model's own key, and `morse-seal` does not do that.
- **It trusts the machine it runs on**, GitHub, and the publisher of `morse-pins`. By default the list follows `main` of `morse-pins`, so the publisher decides which published images you trust, including whether a revoked image is revoked. The source check means every image you trust has public source. The log names the `morse-pins` commit of each image you trusted. To move to a new list only when you choose, pass `--pins-commit`.

## Use the Go packages

The verifier and the seal are Go packages you can import without the sidecar:

- `github.com/trymorse/morse-seal/verify` checks a Morse attestation document and returns the key it binds.
- `github.com/trymorse/morse-seal/seal` seals a request to those keys and opens the sealed reply.

```go
pins, err := verify.ParsePins(data)
key, err := verify.Document(document, verify.Expectation{Environment: "prod", Pins: pins, Root: verify.Root, Now: time.Now()})
```

## How this repository is published

Morse exports this code from its private monorepo when a release that changes it deploys to production. Each commit here is one such release, tagged with its version, such as `v2026.11.0`. A tag builds the release binaries and the container image. Morse does not publish its day-to-day commits.

This repository does not take pull requests. To report a bug, open an issue. To report a security problem, follow `SECURITY.md`.

## License

MIT. See `LICENSE`.

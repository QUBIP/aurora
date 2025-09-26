# `aurora`

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2 licensed][license-image]
![MSRV][rustc-image]


[Report a Bug](https://github.com/qubip/aurora/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+)
·
[Request a Feature](https://github.com/qubip/aurora/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+)
·
[Ask a Question](https://github.com/qubip/aurora/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+)


[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/qubip/aurora/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![code with love by qubip](https://img.shields.io/badge/%3C%2F%3E%20with%20%E2%99%A5%20by-qubip%2Fnisec-ff1414.svg?style=flat-square)](https://github.com/orgs/QUBIP/teams/nisec)


> [!CAUTION]
>
> ### Development in Progress
>
> This project is **currently in development** and **not yet ready for production use**.
>
> **Expect changes** to occur from time to time, and at this stage, some features may be unavailable.

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
<!--
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
!-->
<!--
- [Usage](#usage)
!-->
- [About](#about)
  - [Supported algorithms](#supported-algorithms)
    - [Key Encapsulation Methods](#key-encapsulation-methods)
    - [Digital Signatures](#digital-signatures)
    - [Composite Signatures](#composite-signatures)
- [Roadmap](#roadmap)
- [Support](#support)
- [Project assistance](#project-assistance)
- [Contributing](#contributing)
- [Authors \& contributors](#authors--contributors)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

</details>

---

## About

`aurora` provides a framework to build
[OpenSSL Providers][ossl:man:provider]
tailored for the transition to post-quantum cryptography.

[ossl:man:provider]: https://docs.openssl.org/3.2/man7/provider/

`aurora` showcases an approach we call "shallow loadable modules",
to enhance cryptographic agility
in order to adapt to the rapidly evolving ecosystem
of PQC algorithms and implementations:

- **_shallow_**: refers to the fact that we do not embed
  the cryptographic implementation within the Provider itself,
  but rather we depend on external implementations and provide
  decoupling between the OpenSSL library and your selection
  of external implementations;
- **_loadable modules_**: highlights that our design aims to produce
  modules that can be loaded at runtime into OpenSSL, to provide
  the desired functionality as needed, and seamlessly for OpenSSL
  and applications running on top of it.

> [!NOTE]
> **Note on naming**
>
> The name of the project is Aurora.
> The name of the repository follows `Github` conventions,
> while the corresponding crate name on `crates.io` was not available.
> So the formers is `aurora`, while the latter is `qubip_aurora`.
>
> This crate builds `cdylib` named `aurora`.
> On Linux this usually means that the build output is called
> `libaurora.so`.

### Supported algorithms

While we do not tightly couple with specific implementation choices,
at the moment we support a limited selection of algorithms
and external implementations through our `Adapters`.

The current supported algorithms are summarized in the following tables.

> [!NOTE]
> Future updates to aurora will expand its support
> for additional PQC algorithms
> and other external implementations.


#### Key Encapsulation Methods

| Algorithm                               | Adapter       | PQ/T Hybrid |
| --------------------------------------- | ------------- | ----------- |
| X25519MLKEM768                          | libcrux       | ✅           |
| SecP256r1MLKEM768                       | libcrux       | ✅           |
| X25519MLKEM768Draft00 (⚠️  experimental) | libcrux_draft | ✅           |

#### Digital Signatures

| Algorithm            | Adapter   |
| -------------------- | --------- |
| _ML-DSA-44_          | pqclean |
| _ML-DSA-65_          | pqclean |
| _ML-DSA-87_          | pqclean |
| _SLH-DSA-SHAKE-128f_ | rustcrypto |
| _SLH-DSA-SHAKE-192f_ | slhdsa_c |
| _SLH-DSA-SHAKE-256s_ | slhdsa_c |

#### Composite Signatures

| Algorithm             | Adapter   |
| --------------------- | --------- |
| _ML-DSA-44_ED25519_ | pqclean |
| _ML-DSA-65_ED25519_ | pqclean |

> [!Note]
> The `ML-DSA-{44,65}_ED25519` algorithms also uses `ed25519-dalek`
> for the traditional part of the signature.

<!--
## Getting Started

### Prerequisites

> **[?]**
> What are the project requirements/dependencies?

### Installation

> **[?]**
> Describe how to install and get started with the project.
!-->

<!--
## Usage

> **[?]**
> How does one go about using it?
> Provide various use cases and code examples here.
!-->

## Roadmap

See the [open issues](https://github.com/qubip/aurora/issues) for a list of proposed features (and known issues).

- [Top Feature Requests](https://github.com/qubip/aurora/issues?q=label%3Aenhancement+is%3Aopen+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Top Bugs](https://github.com/qubip/aurora/issues?q=is%3Aissue+is%3Aopen+label%3Abug+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Newest Bugs](https://github.com/qubip/aurora/issues?q=is%3Aopen+is%3Aissue+label%3Abug)

## Support

Reach out to the maintainers at one of the following places:

- [GitHub issues](https://github.com/qubip/aurora/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+)
- <security@romen.dev> to disclose security issues according to our [security documentation](docs/SECURITY.md).
- <coc@romen.dev> to report violations of our [Code of Conduct](docs/CODE_OF_CONDUCT.md).
- Details about the GPG keys to encrypt reports are included in our [security documentation](docs/SECURITY.md).

## Project assistance

If you want to say **thank you** or/and support active development:

- Add a [GitHub Star](https://github.com/qubip/aurora) to the project.
- Mention this project on your social media of choice.
- Write interesting articles about the project, and cite us.

Together, we can make Aurora **better**!

## Contributing

The GitHub repository primarily serves as a mirror,
and will be updated every time a new version is released.
It might not always be updated with the latest commits in between releases.
However, contributions are still very welcome!

Please read [our contribution guidelines](docs/CONTRIBUTING.md), and thank you for being involved!

## Authors & contributors

The original setup of this repository is by [NISEC](https://github.com/orgs/QUBIP/teams/nisec).

For a full list of all authors and contributors, see [the contributors page](https://github.com/qubip/aurora/contributors).

## Security

In this project, we aim to follow good security practices, but 100% security cannot be assured.
This crate is provided **"as is"** without any **warranty**. Use at your own risk.

_For more information and to report security issues, please refer to our [security documentation](docs/SECURITY.md)._

## License

This project is licensed under the
[**Apache License, Version 2.0**](https://www.apache.org/licenses/LICENSE-2.0)
([Apache-2.0](https://spdx.org/licenses/Apache-2.0.html)).

```text
Copyright 2023-2025 Tampere University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

See [LICENSE][LICENSE] for more information.

[LICENSE]: LICENSE

## Acknowledgements

This work has been developed within the QUBIP project (<https://www.qubip.eu>),
funded by the European Union under the Horizon Europe framework programme
[grant agreement no. 101119746](https://doi.org/10.3030/101119746).


[crate-image]: https://img.shields.io/crates/v/qubip_aurora?logo=rust
[crate-link]: https://crates.io/crates/qubip_aurora
[docs-image]: https://docs.rs/qubip_aurora/badge.svg
[docs-link]: https://docs.rs/qubip_aurora/
[build-image]: https://img.shields.io/badge/build-not_automated_yet-red "not automated yet"
[build-link]: # "not automated yet"
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[//]: # "links"


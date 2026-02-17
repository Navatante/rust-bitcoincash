# Roadmap: rust-bitcoincash

Guía de refactorización para adaptar rust-bitcoin a Bitcoin Cash (BCH).

---

## 1. Estado actual del fork

- Fork de **rust-bitcoin v0.33.0-alpha.0**
- Solo cambios cosméticos aplicados hasta ahora: logo, README
- Todo el código BTC sigue intacto y sin modificar

---

## 2. Eliminaciones (código BTC-específico a remover)

### SegWit completo
- Campo `witness` en `TxIn` (`primitives/src/transaction.rs`)
- Struct `Witness` y toda su lógica
- Serialización SegWit: `SEGWIT_MARKER` / `SEGWIT_FLAG`
- Módulos `script/witness_program.rs` y `script/witness_version.rs`

### Taproot
- Directorio `bitcoin/src/taproot/` (~95KB+)
- Opcode `OP_CHECKSIGADD` (0xba en BTC; en BCH ese slot es `OP_CHECKDATASIG`)
- `crypto/taproot.rs` (Schnorr tweaking)
- `TapSighash` y toda la lógica sighash SegWit v1

### Tipos de dirección BTC
- `P2WPKH`, `P2WSH`, `P2TR`, `P2A`
- Codificación **bech32** y **bech32m** (exclusivas de BTC SegWit)

### BIPs exclusivos de BTC
- BIP-152 (compact blocks)
- BIP-158 (block filters / Golomb-coded sets)

### Ejemplos BTC a eliminar
- `sign-tx-taproot`
- `taproot-psbt`
- `create-p2wpkh-address`
- `sign-tx-segwit-v0`

---

## 3. Parámetros de red y consenso

| Parámetro | BTC actual | BCH |
|---|---|---|
| `Bitcoin` network enum | `Bitcoin` | `BitcoinCash` |
| P2PKH prefix (mainnet) | `0x00` | `0x00` (igual, pero CashAddr por defecto) |
| P2SH prefix (mainnet) | `0x05` | `0x05` (igual, pero CashAddr por defecto) |
| `MAX_BLOCK_SERIALIZED_SIZE` | 4 MB | 32 MB (dinámico con ABLA desde mayo 2024) |
| Ajuste de dificultad | `DIFFCHANGE_INTERVAL` (2016 bloques) | **ASERT** (`aserti3-2d`) |
| Magic bytes (mainnet) | `0xF9BEB4D9` | `0xE3E1F3E8` |
| Altura del fork BCH | — | **478 559** (1 agosto 2017) |

### Algoritmos a implementar
- **ASERT (`aserti3-2d`)**: ajuste de dificultad de BCH (activado nov 2020)
- **ABLA** (Adaptive Blocksize Limit Algorithm): límite de bloque dinámico (activado mayo 2024)

### Redes
- Actualizar parámetros de **testnet3**, **testnet4** y **regtest** para BCH
- Prefijos de red: `"bitcoincash:"`, `"bchtest:"`, `"bchreg:"`

---

## 4. Opcodes de script

### A añadir (nuevos en BCH)

| Opcode | Valor | Activación |
|---|---|---|
| `OP_CHECKDATASIG` | `0xba` | Nov 2018 |
| `OP_CHECKDATASIGVERIFY` | `0xbb` | Nov 2018 |
| `OP_SPLIT` | `0x7f` | Nov 2018 |
| `OP_BIN2NUM` | `0x80` | Nov 2018 |
| `OP_NUM2BIN` | `0x81` | Nov 2018 |

**Introspection opcodes** (CHIP-2021-02, activado mayo 2022) — rango `0xc0–0xcf`:

| Opcode | Descripción |
|---|---|
| `OP_INPUTINDEX` | Índice del input actual |
| `OP_ACTIVEBYTECODE` | Bytecode del input activo |
| `OP_TXVERSION` | Versión de la transacción |
| `OP_TXINPUTCOUNT` | Número de inputs |
| `OP_TXOUTPUTCOUNT` | Número de outputs |
| `OP_TXLOCKTIME` | Locktime de la transacción |
| `OP_UTXOVALUE` | Valor del UTXO actual |
| `OP_UTXOBYTECODE` | Bytecode del UTXO actual |
| `OP_OUTPOINTTXHASH` | Txid del outpoint |
| `OP_OUTPOINTINDEX` | Índice del outpoint |
| `OP_INPUTBYTECODE` | Bytecode del input |
| `OP_INPUTSEQUENCENUMBER` | Sequence del input |
| `OP_OUTPUTVALUE` | Valor del output |
| `OP_OUTPUTBYTECODE` | Bytecode del output |
| `OP_UTXOTOKENCOMMITMENT` | Commitment del token del UTXO |

**Mayo 2026 — CashVM / Layla:**

| Opcode | Descripción |
|---|---|
| `OP_BEGIN` / `OP_UNTIL` | Bucles |
| `OP_DEFINE` / `OP_INVOKE` | Funciones |
| `OP_INVERT` | NOT bitwise |
| `OP_LSHIFTNUM` / `OP_RSHIFTNUM` | Shift numérico |
| `OP_LSHIFTBIN` / `OP_RSHIFTBIN` | Shift binario |

### A re-habilitar (desactivados en BTC, activos en BCH)

`OP_CAT`, `OP_SPLIT`, `OP_AND`, `OP_OR`, `OP_XOR`, `OP_DIV`, `OP_MOD`,
`OP_LSHIFT`, `OP_RSHIFT` (con semántica BCH definida)

### A eliminar / reasignar
- `OP_CHECKSIGADD` (0xba en BTC/Taproot) → el slot 0xba es `OP_CHECKDATASIG` en BCH

---

## 5. Formato de transacción y SIGHASH

### Cambios en `TxIn`
- Eliminar campo `witness: Witness`
- Actualizar serialización/deserialización (sin marker/flag SegWit)

### SIGHASH_FORKID
- Implementar `SIGHASH_FORKID` (`0x40`) para replay protection (activo desde el fork)
- Adaptar `sighash.rs`: variante de **BIP143** con `SIGHASH_FORKID` obligatorio
- Eliminar `TapSighash` y toda la lógica SegWit v1

### Serialización
- Sin `SEGWIT_MARKER` (`0x00`) ni `SEGWIT_FLAG` (`0x01`)
- Formato limpio: `version | inputs | outputs | locktime`

---

## 6. Direcciones: CashAddr

Reemplazar bech32 con **CashAddr** como formato de dirección principal de BCH.

### Especificación
- Prefijos: `bitcoincash:` (mainnet), `bchtest:` (testnet), `bchreg:` (regtest)
- Alfabeto Base32 BCH: `qpzry9x8gf2tvdw0s3jn54khce6mua7l`
- Checksum: 40 bits, códigos BCH sobre GF(2⁵)

### Tipos de payload
| Tipo | Valor |
|---|---|
| P2PKH | `0` |
| P2SH | `1` |

### Compatibilidad legacy
- Mantener decodificación **Base58Check** para wallets/exchanges antiguos
- Toda dirección nueva debe generarse en CashAddr

### Módulos afectados
- `bitcoin/src/address/` — refactorizar completamente
- Eliminar `address/witness_program.rs`, `address/witness_version.rs`

---

## 7. CashTokens (CHIP-2022-02, activo mayo 2023)

### Estructura `TokenData` en `TxOut`

```rust
pub struct TokenData {
    /// 32-byte txid del UTXO que creó el token (category ID)
    pub category: Txid,
    /// Cantidad de tokens fungibles (0 si solo NFT)
    pub amount: u64,
    /// Capacidad del NFT: None | Mutable | Minting
    pub nft_capability: Option<NftCapability>,
    /// Commitment del NFT (0–40 bytes)
    pub nft_commitment: Vec<u8>,
}
```

### Serialización
- Prefijo de token en `TxOut` (antes del script)
- Byte de prefijo `0xef` indica presencia de tokens
- Formato: `0xef | category (32B) | bitfield | [amount varint] | [commitment]`

### Reglas de validación
- **Genesis**: solo el primer output de una tx puede crear una categoría nueva
- **Conservación de supply**: suma de tokens fungibles de entrada ≥ suma de salida
- **NFT minting**: solo inputs con capability `minting` pueden crear nuevos NFTs
- **NFT mutable**: puede cambiar su commitment; no puede crear nuevos tokens

### Mayo 2026
- Aumento del límite de commitment de NFT (CHIP-2025-05 P2S)

---

## 8. Mejoras de VM — Mayo 2025 (VELMA)

### CHIP-2021-05: VM Limits
- Eliminar límite de **201 opcodes por script** (reemplazado por límite de densidad)
- Stack element size: **520 bytes → 10 000 bytes**
- Script size: actualizar límites según especificación
- Límite de operaciones: basado en "operación-densidad" del script

### CHIP-2024-07: BigInt
- Enteros de **tamaño arbitrario** (dentro de límites de VM)
- Eliminar límite actual de 64 bits en operaciones aritméticas
- Afecta: `op_add`, `op_sub`, `op_mul`, `op_div`, `op_mod`, `op_lshift`, `op_rshift`

---

## 9. P2P Protocol

| Campo | BTC | BCH |
|---|---|---|
| Magic (mainnet) | `0xF9BEB4D9` | `0xE3E1F3E8` |
| Magic (testnet3) | `0x0B110907` | `0xF4E5F3F4` |
| Magic (regtest) | `0xFABFB5DA` | `0xDAB5BFFA` |

### Cambios en mensajes P2P
- Eliminar mensajes relacionados con witness/SegWit
- Verificar handshake de versión (actualizar `user_agent` y servicios si es necesario)
- Mantener mensajes base: `version`, `verack`, `inv`, `getdata`, `block`, `tx`, `headers`

---

## 10. PSBT

**Decisión pendiente:** evaluar si mantener PSBT adaptado o implementar un formato BCH propio.

### Opción A: PSBT adaptado (BIP-174)
- Remover campos Taproot/witness (`PSBT_IN_TAP_*`, `PSBT_IN_WITNESS_*`)
- Adaptar sighash para `SIGHASH_FORKID`
- Añadir soporte para CashTokens en inputs/outputs

### Opción B: Formato nativo BCH
- Investigar si existe especificación BCHPSBT en la comunidad BCH
- Implementar según especificación si existe

---

## 11. Módulos de criptografía

| Módulo | Acción | Motivo |
|---|---|---|
| `secp256k1` | Mantener | BCH usa ECDSA sobre secp256k1 |
| `ecdsa` | Mantener | Firma estándar de BCH |
| `bip32` (HD wallets) | Mantener | Compatible con BCH |
| `sign_message` | Mantener | Mismo esquema que BTC |
| `crypto/taproot.rs` | **Eliminar** | Schnorr/Taproot no existe en BCH |
| `schnorr` (firmas) | **Evaluar** | BCH no usa Schnorr actualmente |

---

## 12. Documentación y ejemplos

### Ejemplos a crear
- `cashaddr` — codificar/decodificar direcciones CashAddr
- `sighash-forkid` — firmar transacción con SIGHASH_FORKID
- `cashtokens-fungible` — crear y transferir tokens fungibles
- `cashtokens-nft` — crear y transferir NFTs
- `sign-tx-bch` — firma básica de transacción BCH

### Actualizaciones
- `docs/` — reescribir para BCH
- `Cargo.toml` — actualizar `name`, `description`, `keywords`, `categories`, `homepage`
- `README.md` — completar con guía de uso BCH

---

## Orden de implementación sugerido

| Fase | Tarea | Prioridad |
|---|---|---|
| 1 | Parámetros de red y constantes básicas | Alta |
| 2 | Eliminar witness/SegWit de `TxIn` y serialización | Alta |
| 3 | `SIGHASH_FORKID` en `crypto/sighash.rs` | Alta |
| 4 | Opcodes básicos BCH (`OP_CHECKDATASIG`, re-habilitar disabled) | Alta |
| 5 | CashAddr en `addresses/` | Alta |
| 6 | CashTokens (`TxOut` prefix, validación) | Media |
| 7 | ASERT + ABLA | Media |
| 8 | Introspection opcodes (CHIP-2021-02) | Media |
| 9 | VM Limits + BigInt (VELMA, mayo 2025) | Media |
| 10 | Eliminar Taproot completamente | Baja |
| 11 | CashVM / Layla (mayo 2026) | Futura |

---

## Referencias

- [Bitcoin Cash Specification](https://bitcoincashresearch.org)
- [CashAddr format](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
- [CashTokens CHIP-2022-02](https://github.com/bitjson/cashtokens)
- [CHIP-2021-02 Introspection](https://gitlab.com/GeneralProtocols/research/chips/-/blob/master/CHIP-2021-02-Add-Native-Introspection-Opcodes.md)
- [CHIP-2021-05 VM Limits](https://github.com/bitjson/bch-vm-limits)
- [CHIP-2024-07 BigInt](https://github.com/bitjson/bch-bigint)
- [ASERT specification](https://gitlab.com/bitcoin-cash-node/bchn-sw/bitcoincash-upgrade-specifications/-/blob/master/spec/2020-11-15-asert.md)
- [ABLA specification](https://gitlab.com/0353F40E/ebaa)
- [rust-bitcoin source](https://github.com/rust-bitcoin/rust-bitcoin)

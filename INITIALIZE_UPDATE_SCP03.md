**INITIALIZE UPDATE Command Message**

| Code | Value                      | Meaning                        |
| ---- | :------------------------- | ------------------------------ |
| CLA  | '80' - '83' or 'C0' - 'CF' |                                |
| INS  | '50'                       | INITIALIZE UPDATE              |
| P1   | 'xx'                       | Key Version Number             |
| P2   | '00'                       | Reference control parameter P2 |
| Lc   | '08'                       | Length of host challenge       |
| Data | 'xx xx…'                   | Host challenge                 |
| Le   | '00'                       |                                |

**INITIALIZE UPDATE Response Message**

| Name                     | Length   |
| ------------------------ | -------- |
| Key diversification data | 10 bytes |
| Key information          | 3 bytes  |
| Card challenge           | 8 bytes  |
| Card cryptogram          | 8 bytes  |
| Sequence Counter         | 3 bytes  |

The **key diversification data** is data typically used by a backend system to derive the card static keys.
The **key information** includes the Key Version Number, the Secure Channel Protocol identifier, here '03',
and the Secure Channel Protocol “i” parameter used in initiating the Secure Channel Session.
The **card challenge** is an internally generated random or pseudo random number.
The **card cryptogram** is an authentication cryptogram.
**Sequence Counter** is only present when SCP03 is configured for pseudo-random challenge generation.


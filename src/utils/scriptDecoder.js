// Licensed under the MIT License
export const hexToBytes = hex => Uint8Array.from(hex.match(/../g), b => parseInt(b, 16))
export const bytesToUtf8 = bytes => new TextDecoder().decode(bytes)

// All covenant introspection opcodes, sourced from opcodes/mod.rs.
// Used to fingerprint a redeem script as a covenant script.
const COVENANT_OPCODES = new Set([
    0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
    0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
])

export class ScriptError extends Error {
    static UnexpectedEof = new ScriptError('Unexpected end of script')
}

export class ScriptOp {
    constructor(op, value = null) {
        this.op = op
        this.value = value
    }
    isPush() {
        return this.op >= 0x00 && this.op <= 0x60
    }
    getPushData() {
        if (this.op >= 0x01 && this.op <= 0x4e && this.value) return new Uint8Array(this.value)
        return null
    }
}

export function decodeScriptAndEnvelope(scriptHex) {
    try {
        const ops = decodeScript(scriptHex);

        for (const op of ops) {
            const d = op.getPushData();
            if (!d || d.length < 15) continue;

            // Ensure it ends with OP_ENDIF
            if (d[d.length - 1] !== 0x68) continue;

            try {
                const innerOps = decodeScript(d);
                op.innerOps = innerOps;

                // Find the Envelope start: OP_0 (0x00) then OP_IF (0x63)
                const ifIdx = innerOps.findIndex((o, idx) => o.op === 0 && innerOps[idx + 1]?.op === 99);

                if (ifIdx !== -1) {
                    // The protocol is usually the first push after OP_IF
                    const protoOp = innerOps[ifIdx + 2];

                    // We look for the JSON blob.
                    // Heuristic: It's a push and starts with '{' (0x7b)
                    const jsonOp = innerOps.slice(ifIdx + 2).find(o => {
                        const data = o.getPushData();
                        return data && data[0] === 0x7b; // 0x7b is '{'
                    });

                    if (jsonOp) {
                        const rawData = bytesToUtf8(jsonOp.getPushData());
                        op.inscription = {
                            protocol: protoOp?.isPush() ? bytesToUtf8(protoOp.getPushData()) : 'unknown',
                            data: JSON.parse(rawData) // Convert plain JSON string to object
                        };
                    }
                }
            } catch (err) {
                // If JSON.parse fails or script is malformed
                console.warn('Envelope found but content was not valid JSON', err);
            }
        }

        // P2SH redeem script detection: the last pushdata in a P2SH signatureScript is always
        // the redeem script. Try to decode it; if it contains at least one non-push opcode
        // (op > 0x60) it is a script worth expanding. Mark it as a covenant if it uses any
        // covenant introspection opcodes.
        const lastPushOp = [...ops].reverse().find(op => op.getPushData() !== null)
        if (lastPushOp && !lastPushOp.innerOps) {
            const d = lastPushOp.getPushData()
            if (d && d.length >= 5) {
                try {
                    const innerOps = decodeScript(d)
                    if (innerOps.some(o => o.op > 0x60)) {
                        lastPushOp.innerOps = innerOps
                        if (innerOps.some(o => COVENANT_OPCODES.has(o.op))) {
                            lastPushOp.covenant = true
                        }
                    }
                } catch {
                    // not a valid script, ignore
                }
            }
        }

        return { ops };
    } catch {
        return null;
    }
}

export function decodeScript(script) {
    const bytes =
        typeof script === 'string' ? hexToBytes(script) : script instanceof Uint8Array ? script : new Uint8Array(script)
    const ops = []
    let i = 0
    while (i < bytes.length) {
        const op = bytes[i++]
        let value = null
        try {
            if (op >= 0x01 && op <= 0x4b) {
                value = readBytes(bytes, i, op)
                i += op
            } else if (op === 0x4c) {
                const len = readPushLength(bytes, i, 1)
                i += 1
                value = readBytes(bytes, i, len)
                i += len
            } else if (op === 0x4d) {
                const len = readPushLength(bytes, i, 2)
                i += 2
                value = readBytes(bytes, i, len)
                i += len
            } else if (op === 0x4e) {
                const len = readPushLength(bytes, i, 4)
                i += 4
                value = readBytes(bytes, i, len)
                i += len
            }
        } catch (err) {
            throw ScriptError.UnexpectedEof
        }
        ops.push(new ScriptOp(op, value))
    }
    return ops
}

function readBytes(bytes, i, n) {
    if (i + n > bytes.length) throw ScriptError.UnexpectedEof
    return bytes.slice(i, i + n)
}

function readPushLength(bytes, i, sizeBytes) {
    if (i + sizeBytes > bytes.length) throw ScriptError.UnexpectedEof
    let len = 0
    if (sizeBytes === 1) len = bytes[i]
    else if (sizeBytes === 2) len = bytes[i] | (bytes[i + 1] << 8)
    else if (sizeBytes === 4) len = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)
    else throw ScriptError.UnexpectedEof
    return len
}
